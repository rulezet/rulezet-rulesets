rule TTP_XOR_QUAD_CurrentVersionRun_6fe6 {
  strings:
    $key_6fe6 = { 3c 89 [2] 18 87 [2] 33 ab [2] 1d 89 [2] 09 92 [2] 06 88 [2] 18 95 [2] 1a 94 [2] 01 92 [2] 1d 95 [2] 01 ba }

  condition:
    any of them
}