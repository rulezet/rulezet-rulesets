rule TTP_XOR_QUAD_CurrentVersionRun_cee6 {
  strings:
    $key_cee6 = { 9d 89 [2] b9 87 [2] 92 ab [2] bc 89 [2] a8 92 [2] a7 88 [2] b9 95 [2] bb 94 [2] a0 92 [2] bc 95 [2] a0 ba }

  condition:
    any of them
}