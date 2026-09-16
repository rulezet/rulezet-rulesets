rule TTP_XOR_QUAD_CurrentVersionRun_d5e6 {
  strings:
    $key_d5e6 = { 86 89 [2] a2 87 [2] 89 ab [2] a7 89 [2] b3 92 [2] bc 88 [2] a2 95 [2] a0 94 [2] bb 92 [2] a7 95 [2] bb ba }

  condition:
    any of them
}