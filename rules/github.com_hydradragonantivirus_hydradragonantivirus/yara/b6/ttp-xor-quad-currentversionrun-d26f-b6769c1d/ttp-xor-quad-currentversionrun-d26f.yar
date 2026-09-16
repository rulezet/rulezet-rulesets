rule TTP_XOR_QUAD_CurrentVersionRun_d26f {
  strings:
    $key_d26f = { 81 00 [2] a5 0e [2] 8e 22 [2] a0 00 [2] b4 1b [2] bb 01 [2] a5 1c [2] a7 1d [2] bc 1b [2] a0 1c [2] bc 33 }

  condition:
    any of them
}