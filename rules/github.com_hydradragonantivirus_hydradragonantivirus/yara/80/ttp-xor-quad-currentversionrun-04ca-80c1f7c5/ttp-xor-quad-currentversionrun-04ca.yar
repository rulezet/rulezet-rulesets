rule TTP_XOR_QUAD_CurrentVersionRun_04ca {
  strings:
    $key_04ca = { 57 a5 [2] 73 ab [2] 58 87 [2] 76 a5 [2] 62 be [2] 6d a4 [2] 73 b9 [2] 71 b8 [2] 6a be [2] 76 b9 [2] 6a 96 }

  condition:
    any of them
}