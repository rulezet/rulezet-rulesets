rule TTP_XOR_QUAD_CurrentVersionRun_c97c {
  strings:
    $key_c97c = { 9a 13 [2] be 1d [2] 95 31 [2] bb 13 [2] af 08 [2] a0 12 [2] be 0f [2] bc 0e [2] a7 08 [2] bb 0f [2] a7 20 }

  condition:
    any of them
}