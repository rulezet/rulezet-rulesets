rule TTP_XOR_QUAD_CurrentVersionRun_d57e {
  strings:
    $key_d57e = { 86 11 [2] a2 1f [2] 89 33 [2] a7 11 [2] b3 0a [2] bc 10 [2] a2 0d [2] a0 0c [2] bb 0a [2] a7 0d [2] bb 22 }

  condition:
    any of them
}