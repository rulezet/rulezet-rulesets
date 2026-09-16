rule TTP_XOR_QUAD_CurrentVersionRun_6fca {
  strings:
    $key_6fca = { 3c a5 [2] 18 ab [2] 33 87 [2] 1d a5 [2] 09 be [2] 06 a4 [2] 18 b9 [2] 1a b8 [2] 01 be [2] 1d b9 [2] 01 96 }

  condition:
    any of them
}