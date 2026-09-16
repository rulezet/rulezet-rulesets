rule TTP_XOR_QUAD_CurrentVersionRun_42ca {
  strings:
    $key_42ca = { 11 a5 [2] 35 ab [2] 1e 87 [2] 30 a5 [2] 24 be [2] 2b a4 [2] 35 b9 [2] 37 b8 [2] 2c be [2] 30 b9 [2] 2c 96 }

  condition:
    any of them
}