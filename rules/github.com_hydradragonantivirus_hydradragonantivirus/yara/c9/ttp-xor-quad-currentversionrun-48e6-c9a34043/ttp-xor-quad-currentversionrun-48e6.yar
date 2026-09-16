rule TTP_XOR_QUAD_CurrentVersionRun_48e6 {
  strings:
    $key_48e6 = { 1b 89 [2] 3f 87 [2] 14 ab [2] 3a 89 [2] 2e 92 [2] 21 88 [2] 3f 95 [2] 3d 94 [2] 26 92 [2] 3a 95 [2] 26 ba }

  condition:
    any of them
}