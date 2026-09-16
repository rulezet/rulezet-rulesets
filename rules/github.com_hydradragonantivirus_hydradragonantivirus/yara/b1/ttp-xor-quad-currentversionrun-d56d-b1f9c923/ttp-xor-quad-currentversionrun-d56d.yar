rule TTP_XOR_QUAD_CurrentVersionRun_d56d {
  strings:
    $key_d56d = { 86 02 [2] a2 0c [2] 89 20 [2] a7 02 [2] b3 19 [2] bc 03 [2] a2 1e [2] a0 1f [2] bb 19 [2] a7 1e [2] bb 31 }

  condition:
    any of them
}