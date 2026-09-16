rule TTP_XOR_QUAD_CurrentVersionRun_16ca {
  strings:
    $key_16ca = { 45 a5 [2] 61 ab [2] 4a 87 [2] 64 a5 [2] 70 be [2] 7f a4 [2] 61 b9 [2] 63 b8 [2] 78 be [2] 64 b9 [2] 78 96 }

  condition:
    any of them
}