rule TTP_XOR_QUAD_CurrentVersionRun_dae5 {
  strings:
    $key_dae5 = { 89 8a [2] ad 84 [2] 86 a8 [2] a8 8a [2] bc 91 [2] b3 8b [2] ad 96 [2] af 97 [2] b4 91 [2] a8 96 [2] b4 b9 }

  condition:
    any of them
}