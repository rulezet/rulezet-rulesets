rule TTP_XOR_QUAD_CurrentVersionRun_0fca {
  strings:
    $key_0fca = { 5c a5 [2] 78 ab [2] 53 87 [2] 7d a5 [2] 69 be [2] 66 a4 [2] 78 b9 [2] 7a b8 [2] 61 be [2] 7d b9 [2] 61 96 }

  condition:
    any of them
}