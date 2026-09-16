rule TTP_XOR_QUAD_CurrentVersionRun_dafa {
  strings:
    $key_dafa = { 89 95 [2] ad 9b [2] 86 b7 [2] a8 95 [2] bc 8e [2] b3 94 [2] ad 89 [2] af 88 [2] b4 8e [2] a8 89 [2] b4 a6 }

  condition:
    any of them
}