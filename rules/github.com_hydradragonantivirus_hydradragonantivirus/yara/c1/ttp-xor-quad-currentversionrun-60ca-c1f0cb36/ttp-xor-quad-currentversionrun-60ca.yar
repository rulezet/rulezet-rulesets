rule TTP_XOR_QUAD_CurrentVersionRun_60ca {
  strings:
    $key_60ca = { 33 a5 [2] 17 ab [2] 3c 87 [2] 12 a5 [2] 06 be [2] 09 a4 [2] 17 b9 [2] 15 b8 [2] 0e be [2] 12 b9 [2] 0e 96 }

  condition:
    any of them
}