rule TTP_XOR_QUAD_CurrentVersionRun_40e6 {
  strings:
    $key_40e6 = { 13 89 [2] 37 87 [2] 1c ab [2] 32 89 [2] 26 92 [2] 29 88 [2] 37 95 [2] 35 94 [2] 2e 92 [2] 32 95 [2] 2e ba }

  condition:
    any of them
}