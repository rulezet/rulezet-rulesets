rule TTP_XOR_QUAD_CurrentVersionRun_56ca {
  strings:
    $key_56ca = { 05 a5 [2] 21 ab [2] 0a 87 [2] 24 a5 [2] 30 be [2] 3f a4 [2] 21 b9 [2] 23 b8 [2] 38 be [2] 24 b9 [2] 38 96 }

  condition:
    any of them
}