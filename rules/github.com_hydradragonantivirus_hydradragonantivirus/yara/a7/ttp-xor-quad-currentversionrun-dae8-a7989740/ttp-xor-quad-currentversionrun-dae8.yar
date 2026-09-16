rule TTP_XOR_QUAD_CurrentVersionRun_dae8 {
  strings:
    $key_dae8 = { 89 87 [2] ad 89 [2] 86 a5 [2] a8 87 [2] bc 9c [2] b3 86 [2] ad 9b [2] af 9a [2] b4 9c [2] a8 9b [2] b4 b4 }

  condition:
    any of them
}