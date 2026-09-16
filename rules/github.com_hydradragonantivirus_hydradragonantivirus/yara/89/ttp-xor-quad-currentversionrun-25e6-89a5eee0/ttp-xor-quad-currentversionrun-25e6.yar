rule TTP_XOR_QUAD_CurrentVersionRun_25e6 {
  strings:
    $key_25e6 = { 76 89 [2] 52 87 [2] 79 ab [2] 57 89 [2] 43 92 [2] 4c 88 [2] 52 95 [2] 50 94 [2] 4b 92 [2] 57 95 [2] 4b ba }

  condition:
    any of them
}