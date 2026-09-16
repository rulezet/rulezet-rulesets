rule TTP_XOR_QUAD_CurrentVersionRun_52ca {
  strings:
    $key_52ca = { 01 a5 [2] 25 ab [2] 0e 87 [2] 20 a5 [2] 34 be [2] 3b a4 [2] 25 b9 [2] 27 b8 [2] 3c be [2] 20 b9 [2] 3c 96 }

  condition:
    any of them
}