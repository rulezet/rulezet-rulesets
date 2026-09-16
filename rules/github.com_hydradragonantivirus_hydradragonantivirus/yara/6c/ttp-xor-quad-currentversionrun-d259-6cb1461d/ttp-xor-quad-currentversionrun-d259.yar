rule TTP_XOR_QUAD_CurrentVersionRun_d259 {
  strings:
    $key_d259 = { 81 36 [2] a5 38 [2] 8e 14 [2] a0 36 [2] b4 2d [2] bb 37 [2] a5 2a [2] a7 2b [2] bc 2d [2] a0 2a [2] bc 05 }

  condition:
    any of them
}