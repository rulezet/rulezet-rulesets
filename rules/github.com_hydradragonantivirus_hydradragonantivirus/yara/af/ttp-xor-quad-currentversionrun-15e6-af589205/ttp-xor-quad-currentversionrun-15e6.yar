rule TTP_XOR_QUAD_CurrentVersionRun_15e6 {
  strings:
    $key_15e6 = { 46 89 [2] 62 87 [2] 49 ab [2] 67 89 [2] 73 92 [2] 7c 88 [2] 62 95 [2] 60 94 [2] 7b 92 [2] 67 95 [2] 7b ba }

  condition:
    any of them
}