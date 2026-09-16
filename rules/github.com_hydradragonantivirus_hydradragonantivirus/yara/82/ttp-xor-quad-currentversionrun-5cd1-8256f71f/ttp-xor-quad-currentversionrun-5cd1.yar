rule TTP_XOR_QUAD_CurrentVersionRun_5cd1 {
  strings:
    $key_5cd1 = { 0f be [2] 2b b0 [2] 00 9c [2] 2e be [2] 3a a5 [2] 35 bf [2] 2b a2 [2] 29 a3 [2] 32 a5 [2] 2e a2 [2] 32 8d }

  condition:
    any of them
}