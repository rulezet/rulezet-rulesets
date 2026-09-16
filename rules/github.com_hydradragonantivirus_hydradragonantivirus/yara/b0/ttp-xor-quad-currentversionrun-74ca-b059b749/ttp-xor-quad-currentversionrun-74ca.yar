rule TTP_XOR_QUAD_CurrentVersionRun_74ca {
  strings:
    $key_74ca = { 27 a5 [2] 03 ab [2] 28 87 [2] 06 a5 [2] 12 be [2] 1d a4 [2] 03 b9 [2] 01 b8 [2] 1a be [2] 06 b9 [2] 1a 96 }

  condition:
    any of them
}