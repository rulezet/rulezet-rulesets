rule TTP_XOR_QUAD_CurrentVersionRun_dae6 {
  strings:
    $key_dae6 = { 89 89 [2] ad 87 [2] 86 ab [2] a8 89 [2] bc 92 [2] b3 88 [2] ad 95 [2] af 94 [2] b4 92 [2] a8 95 [2] b4 ba }

  condition:
    any of them
}