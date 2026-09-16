rule TTP_XOR_QUAD_CurrentVersionRun_69e6 {
  strings:
    $key_69e6 = { 3a 89 [2] 1e 87 [2] 35 ab [2] 1b 89 [2] 0f 92 [2] 00 88 [2] 1e 95 [2] 1c 94 [2] 07 92 [2] 1b 95 [2] 07 ba }

  condition:
    any of them
}