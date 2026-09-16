rule TTP_XOR_QUAD_CurrentVersionRun_d55f {
  strings:
    $key_d55f = { 86 30 [2] a2 3e [2] 89 12 [2] a7 30 [2] b3 2b [2] bc 31 [2] a2 2c [2] a0 2d [2] bb 2b [2] a7 2c [2] bb 03 }

  condition:
    any of them
}