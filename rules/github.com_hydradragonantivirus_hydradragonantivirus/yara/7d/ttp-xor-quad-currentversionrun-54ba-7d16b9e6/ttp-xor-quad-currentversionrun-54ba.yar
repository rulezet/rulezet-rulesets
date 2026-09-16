rule TTP_XOR_QUAD_CurrentVersionRun_54ba {
  strings:
    $key_54ba = { 07 d5 [2] 23 db [2] 08 f7 [2] 26 d5 [2] 32 ce [2] 3d d4 [2] 23 c9 [2] 21 c8 [2] 3a ce [2] 26 c9 [2] 3a e6 }

  condition:
    any of them
}