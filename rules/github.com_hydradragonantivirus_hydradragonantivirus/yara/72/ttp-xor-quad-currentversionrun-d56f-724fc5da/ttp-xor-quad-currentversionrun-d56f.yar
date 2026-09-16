rule TTP_XOR_QUAD_CurrentVersionRun_d56f {
  strings:
    $key_d56f = { 86 00 [2] a2 0e [2] 89 22 [2] a7 00 [2] b3 1b [2] bc 01 [2] a2 1c [2] a0 1d [2] bb 1b [2] a7 1c [2] bb 33 }

  condition:
    any of them
}