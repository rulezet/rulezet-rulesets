rule TTP_XOR_QUAD_CurrentVersionRun_d56c {
  strings:
    $key_d56c = { 86 03 [2] a2 0d [2] 89 21 [2] a7 03 [2] b3 18 [2] bc 02 [2] a2 1f [2] a0 1e [2] bb 18 [2] a7 1f [2] bb 30 }

  condition:
    any of them
}