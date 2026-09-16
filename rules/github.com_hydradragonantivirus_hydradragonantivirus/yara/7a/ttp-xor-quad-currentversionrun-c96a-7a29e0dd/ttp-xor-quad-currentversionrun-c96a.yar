rule TTP_XOR_QUAD_CurrentVersionRun_c96a {
  strings:
    $key_c96a = { 9a 05 [2] be 0b [2] 95 27 [2] bb 05 [2] af 1e [2] a0 04 [2] be 19 [2] bc 18 [2] a7 1e [2] bb 19 [2] a7 36 }

  condition:
    any of them
}