rule TTP_XOR_QUAD_CurrentVersionRun_dae1 {
  strings:
    $key_dae1 = { 89 8e [2] ad 80 [2] 86 ac [2] a8 8e [2] bc 95 [2] b3 8f [2] ad 92 [2] af 93 [2] b4 95 [2] a8 92 [2] b4 bd }

  condition:
    any of them
}