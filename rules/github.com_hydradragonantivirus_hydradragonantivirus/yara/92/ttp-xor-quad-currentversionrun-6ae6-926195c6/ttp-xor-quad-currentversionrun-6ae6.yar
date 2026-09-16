rule TTP_XOR_QUAD_CurrentVersionRun_6ae6 {
  strings:
    $key_6ae6 = { 39 89 [2] 1d 87 [2] 36 ab [2] 18 89 [2] 0c 92 [2] 03 88 [2] 1d 95 [2] 1f 94 [2] 04 92 [2] 18 95 [2] 04 ba }

  condition:
    any of them
}