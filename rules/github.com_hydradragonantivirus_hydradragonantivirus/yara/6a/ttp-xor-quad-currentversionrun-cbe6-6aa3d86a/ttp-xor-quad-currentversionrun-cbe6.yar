rule TTP_XOR_QUAD_CurrentVersionRun_cbe6 {
  strings:
    $key_cbe6 = { 98 89 [2] bc 87 [2] 97 ab [2] b9 89 [2] ad 92 [2] a2 88 [2] bc 95 [2] be 94 [2] a5 92 [2] b9 95 [2] a5 ba }

  condition:
    any of them
}