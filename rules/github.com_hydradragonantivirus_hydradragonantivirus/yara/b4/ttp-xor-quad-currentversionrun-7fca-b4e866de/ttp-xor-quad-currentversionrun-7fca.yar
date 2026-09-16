rule TTP_XOR_QUAD_CurrentVersionRun_7fca {
  strings:
    $key_7fca = { 2c a5 [2] 08 ab [2] 23 87 [2] 0d a5 [2] 19 be [2] 16 a4 [2] 08 b9 [2] 0a b8 [2] 11 be [2] 0d b9 [2] 11 96 }

  condition:
    any of them
}