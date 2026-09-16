rule TTP_XOR_QUAD_CurrentVersionRun_dae9 {
  strings:
    $key_dae9 = { 89 86 [2] ad 88 [2] 86 a4 [2] a8 86 [2] bc 9d [2] b3 87 [2] ad 9a [2] af 9b [2] b4 9d [2] a8 9a [2] b4 b5 }

  condition:
    any of them
}