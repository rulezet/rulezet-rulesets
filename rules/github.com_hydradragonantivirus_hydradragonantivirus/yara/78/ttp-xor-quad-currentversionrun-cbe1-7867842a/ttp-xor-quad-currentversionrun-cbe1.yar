rule TTP_XOR_QUAD_CurrentVersionRun_cbe1 {
  strings:
    $key_cbe1 = { 98 8e [2] bc 80 [2] 97 ac [2] b9 8e [2] ad 95 [2] a2 8f [2] bc 92 [2] be 93 [2] a5 95 [2] b9 92 [2] a5 bd }

  condition:
    any of them
}