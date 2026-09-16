rule TTP_XOR_QUAD_CurrentVersionRun_07e6 {
  strings:
    $key_07e6 = { 54 89 [2] 70 87 [2] 5b ab [2] 75 89 [2] 61 92 [2] 6e 88 [2] 70 95 [2] 72 94 [2] 69 92 [2] 75 95 [2] 69 ba }

  condition:
    any of them
}