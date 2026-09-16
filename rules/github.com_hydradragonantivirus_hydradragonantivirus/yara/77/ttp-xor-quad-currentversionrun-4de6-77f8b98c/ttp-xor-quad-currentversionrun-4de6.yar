rule TTP_XOR_QUAD_CurrentVersionRun_4de6 {
  strings:
    $key_4de6 = { 1e 89 [2] 3a 87 [2] 11 ab [2] 3f 89 [2] 2b 92 [2] 24 88 [2] 3a 95 [2] 38 94 [2] 23 92 [2] 3f 95 [2] 23 ba }

  condition:
    any of them
}