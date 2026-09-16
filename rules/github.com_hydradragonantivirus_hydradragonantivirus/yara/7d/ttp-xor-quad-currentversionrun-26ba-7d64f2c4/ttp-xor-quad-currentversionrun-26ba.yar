rule TTP_XOR_QUAD_CurrentVersionRun_26ba {
  strings:
    $key_26ba = { 75 d5 [2] 51 db [2] 7a f7 [2] 54 d5 [2] 40 ce [2] 4f d4 [2] 51 c9 [2] 53 c8 [2] 48 ce [2] 54 c9 [2] 48 e6 }

  condition:
    any of them
}