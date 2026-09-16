rule TTP_XOR_QUAD_CurrentVersionRun_48ba {
  strings:
    $key_48ba = { 1b d5 [2] 3f db [2] 14 f7 [2] 3a d5 [2] 2e ce [2] 21 d4 [2] 3f c9 [2] 3d c8 [2] 26 ce [2] 3a c9 [2] 26 e6 }

  condition:
    any of them
}