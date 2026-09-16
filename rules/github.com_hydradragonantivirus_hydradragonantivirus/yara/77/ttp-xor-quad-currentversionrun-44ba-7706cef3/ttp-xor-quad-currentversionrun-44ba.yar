rule TTP_XOR_QUAD_CurrentVersionRun_44ba {
  strings:
    $key_44ba = { 17 d5 [2] 33 db [2] 18 f7 [2] 36 d5 [2] 22 ce [2] 2d d4 [2] 33 c9 [2] 31 c8 [2] 2a ce [2] 36 c9 [2] 2a e6 }

  condition:
    any of them
}