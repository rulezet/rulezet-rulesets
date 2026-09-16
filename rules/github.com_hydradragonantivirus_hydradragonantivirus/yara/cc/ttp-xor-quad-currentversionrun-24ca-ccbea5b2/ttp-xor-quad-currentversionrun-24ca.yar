rule TTP_XOR_QUAD_CurrentVersionRun_24ca {
  strings:
    $key_24ca = { 77 a5 [2] 53 ab [2] 78 87 [2] 56 a5 [2] 42 be [2] 4d a4 [2] 53 b9 [2] 51 b8 [2] 4a be [2] 56 b9 [2] 4a 96 }

  condition:
    any of them
}