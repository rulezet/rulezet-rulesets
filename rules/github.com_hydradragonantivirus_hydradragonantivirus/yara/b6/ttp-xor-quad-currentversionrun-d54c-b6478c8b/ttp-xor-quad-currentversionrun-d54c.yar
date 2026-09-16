rule TTP_XOR_QUAD_CurrentVersionRun_d54c {
  strings:
    $key_d54c = { 86 23 [2] a2 2d [2] 89 01 [2] a7 23 [2] b3 38 [2] bc 22 [2] a2 3f [2] a0 3e [2] bb 38 [2] a7 3f [2] bb 10 }

  condition:
    any of them
}