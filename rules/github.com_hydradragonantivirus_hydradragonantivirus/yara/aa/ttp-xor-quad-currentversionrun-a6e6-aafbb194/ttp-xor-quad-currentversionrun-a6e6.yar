rule TTP_XOR_QUAD_CurrentVersionRun_a6e6 {
  strings:
    $key_a6e6 = { f5 89 [2] d1 87 [2] fa ab [2] d4 89 [2] c0 92 [2] cf 88 [2] d1 95 [2] d3 94 [2] c8 92 [2] d4 95 [2] c8 ba }

  condition:
    any of them
}