rule TTP_XOR_QUAD_CurrentVersionRun_34ba {
  strings:
    $key_34ba = { 67 d5 [2] 43 db [2] 68 f7 [2] 46 d5 [2] 52 ce [2] 5d d4 [2] 43 c9 [2] 41 c8 [2] 5a ce [2] 46 c9 [2] 5a e6 }

  condition:
    any of them
}