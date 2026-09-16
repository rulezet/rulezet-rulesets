rule TTP_XOR_QUAD_CurrentVersionRun_d24e {
  strings:
    $key_d24e = { 81 21 [2] a5 2f [2] 8e 03 [2] a0 21 [2] b4 3a [2] bb 20 [2] a5 3d [2] a7 3c [2] bc 3a [2] a0 3d [2] bc 12 }

  condition:
    any of them
}