rule TTP_XOR_QUAD_CurrentVersionRun_dae4 {
  strings:
    $key_dae4 = { 89 8b [2] ad 85 [2] 86 a9 [2] a8 8b [2] bc 90 [2] b3 8a [2] ad 97 [2] af 96 [2] b4 90 [2] a8 97 [2] b4 b8 }

  condition:
    any of them
}