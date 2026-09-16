rule TTP_XOR_QUAD_CurrentVersionRun_a1e6 {
  strings:
    $key_a1e6 = { f2 89 [2] d6 87 [2] fd ab [2] d3 89 [2] c7 92 [2] c8 88 [2] d6 95 [2] d4 94 [2] cf 92 [2] d3 95 [2] cf ba }

  condition:
    any of them
}