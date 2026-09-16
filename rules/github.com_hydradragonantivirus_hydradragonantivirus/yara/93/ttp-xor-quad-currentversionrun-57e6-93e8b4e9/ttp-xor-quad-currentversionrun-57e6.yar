rule TTP_XOR_QUAD_CurrentVersionRun_57e6 {
  strings:
    $key_57e6 = { 04 89 [2] 20 87 [2] 0b ab [2] 25 89 [2] 31 92 [2] 3e 88 [2] 20 95 [2] 22 94 [2] 39 92 [2] 25 95 [2] 39 ba }

  condition:
    any of them
}