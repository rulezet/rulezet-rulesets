rule TTP_XOR_QUAD_CurrentVersionRun_01ba {
  strings:
    $key_01ba = { 52 d5 [2] 76 db [2] 5d f7 [2] 73 d5 [2] 67 ce [2] 68 d4 [2] 76 c9 [2] 74 c8 [2] 6f ce [2] 73 c9 [2] 6f e6 }

  condition:
    any of them
}