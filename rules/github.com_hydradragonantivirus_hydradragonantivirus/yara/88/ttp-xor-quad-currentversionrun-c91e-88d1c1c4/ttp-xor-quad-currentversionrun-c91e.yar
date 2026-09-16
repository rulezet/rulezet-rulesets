rule TTP_XOR_QUAD_CurrentVersionRun_c91e {
  strings:
    $key_c91e = { 9a 71 [2] be 7f [2] 95 53 [2] bb 71 [2] af 6a [2] a0 70 [2] be 6d [2] bc 6c [2] a7 6a [2] bb 6d [2] a7 42 }

  condition:
    any of them
}