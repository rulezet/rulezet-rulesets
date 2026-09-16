rule TTP_XOR_QUAD_CurrentVersionRun_14ca {
  strings:
    $key_14ca = { 47 a5 [2] 63 ab [2] 48 87 [2] 66 a5 [2] 72 be [2] 7d a4 [2] 63 b9 [2] 61 b8 [2] 7a be [2] 66 b9 [2] 7a 96 }

  condition:
    any of them
}