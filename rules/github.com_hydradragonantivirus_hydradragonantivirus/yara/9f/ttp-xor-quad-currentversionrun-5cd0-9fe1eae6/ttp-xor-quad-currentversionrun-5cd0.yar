rule TTP_XOR_QUAD_CurrentVersionRun_5cd0 {
  strings:
    $key_5cd0 = { 0f bf [2] 2b b1 [2] 00 9d [2] 2e bf [2] 3a a4 [2] 35 be [2] 2b a3 [2] 29 a2 [2] 32 a4 [2] 2e a3 [2] 32 8c }

  condition:
    any of them
}