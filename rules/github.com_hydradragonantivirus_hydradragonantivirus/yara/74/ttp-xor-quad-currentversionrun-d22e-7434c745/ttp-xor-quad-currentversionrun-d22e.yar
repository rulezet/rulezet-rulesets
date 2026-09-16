rule TTP_XOR_QUAD_CurrentVersionRun_d22e {
  strings:
    $key_d22e = { 81 41 [2] a5 4f [2] 8e 63 [2] a0 41 [2] b4 5a [2] bb 40 [2] a5 5d [2] a7 5c [2] bc 5a [2] a0 5d [2] bc 72 }

  condition:
    any of them
}