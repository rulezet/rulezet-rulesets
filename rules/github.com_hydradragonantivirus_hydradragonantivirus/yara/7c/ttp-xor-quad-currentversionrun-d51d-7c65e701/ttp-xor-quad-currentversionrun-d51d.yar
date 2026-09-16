rule TTP_XOR_QUAD_CurrentVersionRun_d51d {
  strings:
    $key_d51d = { 86 72 [2] a2 7c [2] 89 50 [2] a7 72 [2] b3 69 [2] bc 73 [2] a2 6e [2] a0 6f [2] bb 69 [2] a7 6e [2] bb 41 }

  condition:
    any of them
}