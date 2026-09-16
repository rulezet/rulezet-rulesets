rule TTP_XOR_QUAD_CurrentVersionRun_c92e {
  strings:
    $key_c92e = { 9a 41 [2] be 4f [2] 95 63 [2] bb 41 [2] af 5a [2] a0 40 [2] be 5d [2] bc 5c [2] a7 5a [2] bb 5d [2] a7 72 }

  condition:
    any of them
}