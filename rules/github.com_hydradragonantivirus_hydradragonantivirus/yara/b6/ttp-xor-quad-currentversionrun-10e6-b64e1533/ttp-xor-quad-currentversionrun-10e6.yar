rule TTP_XOR_QUAD_CurrentVersionRun_10e6 {
  strings:
    $key_10e6 = { 43 89 [2] 67 87 [2] 4c ab [2] 62 89 [2] 76 92 [2] 79 88 [2] 67 95 [2] 65 94 [2] 7e 92 [2] 62 95 [2] 7e ba }

  condition:
    any of them
}