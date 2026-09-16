rule TTP_XOR_QUAD_CurrentVersionRun_c93c {
  strings:
    $key_c93c = { 9a 53 [2] be 5d [2] 95 71 [2] bb 53 [2] af 48 [2] a0 52 [2] be 4f [2] bc 4e [2] a7 48 [2] bb 4f [2] a7 60 }

  condition:
    any of them
}