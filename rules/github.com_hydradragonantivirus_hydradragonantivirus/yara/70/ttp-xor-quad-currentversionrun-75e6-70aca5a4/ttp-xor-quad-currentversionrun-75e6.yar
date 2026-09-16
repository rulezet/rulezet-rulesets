rule TTP_XOR_QUAD_CurrentVersionRun_75e6 {
  strings:
    $key_75e6 = { 26 89 [2] 02 87 [2] 29 ab [2] 07 89 [2] 13 92 [2] 1c 88 [2] 02 95 [2] 00 94 [2] 1b 92 [2] 07 95 [2] 1b ba }

  condition:
    any of them
}