rule TTP_XOR_QUAD_CurrentVersionRun_78ba {
  strings:
    $key_78ba = { 2b d5 [2] 0f db [2] 24 f7 [2] 0a d5 [2] 1e ce [2] 11 d4 [2] 0f c9 [2] 0d c8 [2] 16 ce [2] 0a c9 [2] 16 e6 }

  condition:
    any of them
}