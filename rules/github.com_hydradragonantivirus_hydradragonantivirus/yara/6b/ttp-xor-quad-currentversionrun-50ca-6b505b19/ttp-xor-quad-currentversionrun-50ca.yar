rule TTP_XOR_QUAD_CurrentVersionRun_50ca {
  strings:
    $key_50ca = { 03 a5 [2] 27 ab [2] 0c 87 [2] 22 a5 [2] 36 be [2] 39 a4 [2] 27 b9 [2] 25 b8 [2] 3e be [2] 22 b9 [2] 3e 96 }

  condition:
    any of them
}