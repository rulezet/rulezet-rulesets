rule TTP_XOR_QUAD_CurrentVersionRun_37e6 {
  strings:
    $key_37e6 = { 64 89 [2] 40 87 [2] 6b ab [2] 45 89 [2] 51 92 [2] 5e 88 [2] 40 95 [2] 42 94 [2] 59 92 [2] 45 95 [2] 59 ba }

  condition:
    any of them
}