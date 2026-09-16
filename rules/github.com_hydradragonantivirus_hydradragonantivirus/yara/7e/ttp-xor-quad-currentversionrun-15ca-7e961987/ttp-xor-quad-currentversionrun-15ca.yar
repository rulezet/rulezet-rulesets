rule TTP_XOR_QUAD_CurrentVersionRun_15ca {
  strings:
    $key_15ca = { 46 a5 [2] 62 ab [2] 49 87 [2] 67 a5 [2] 73 be [2] 7c a4 [2] 62 b9 [2] 60 b8 [2] 7b be [2] 67 b9 [2] 7b 96 }

  condition:
    any of them
}