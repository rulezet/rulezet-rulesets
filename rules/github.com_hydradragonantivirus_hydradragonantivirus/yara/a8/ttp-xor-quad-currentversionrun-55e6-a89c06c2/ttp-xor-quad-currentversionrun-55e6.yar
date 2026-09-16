rule TTP_XOR_QUAD_CurrentVersionRun_55e6 {
  strings:
    $key_55e6 = { 06 89 [2] 22 87 [2] 09 ab [2] 27 89 [2] 33 92 [2] 3c 88 [2] 22 95 [2] 20 94 [2] 3b 92 [2] 27 95 [2] 3b ba }

  condition:
    any of them
}