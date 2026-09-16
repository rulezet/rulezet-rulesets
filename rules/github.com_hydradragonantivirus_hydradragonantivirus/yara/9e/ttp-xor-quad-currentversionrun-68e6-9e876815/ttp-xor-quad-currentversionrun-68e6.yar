rule TTP_XOR_QUAD_CurrentVersionRun_68e6 {
  strings:
    $key_68e6 = { 3b 89 [2] 1f 87 [2] 34 ab [2] 1a 89 [2] 0e 92 [2] 01 88 [2] 1f 95 [2] 1d 94 [2] 06 92 [2] 1a 95 [2] 06 ba }

  condition:
    any of them
}