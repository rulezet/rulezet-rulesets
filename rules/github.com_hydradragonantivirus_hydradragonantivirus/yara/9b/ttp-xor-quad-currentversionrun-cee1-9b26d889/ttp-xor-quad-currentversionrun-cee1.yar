rule TTP_XOR_QUAD_CurrentVersionRun_cee1 {
  strings:
    $key_cee1 = { 9d 8e [2] b9 80 [2] 92 ac [2] bc 8e [2] a8 95 [2] a7 8f [2] b9 92 [2] bb 93 [2] a0 95 [2] bc 92 [2] a0 bd }

  condition:
    any of them
}