rule TTP_XOR_QUAD_CurrentVersionRun_5fe6 {
  strings:
    $key_5fe6 = { 0c 89 [2] 28 87 [2] 03 ab [2] 2d 89 [2] 39 92 [2] 36 88 [2] 28 95 [2] 2a 94 [2] 31 92 [2] 2d 95 [2] 31 ba }

  condition:
    any of them
}