rule TTP_XOR_QUAD_CurrentVersionRun_c90d {
  strings:
    $key_c90d = { 9a 62 [2] be 6c [2] 95 40 [2] bb 62 [2] af 79 [2] a0 63 [2] be 7e [2] bc 7f [2] a7 79 [2] bb 7e [2] a7 51 }

  condition:
    any of them
}