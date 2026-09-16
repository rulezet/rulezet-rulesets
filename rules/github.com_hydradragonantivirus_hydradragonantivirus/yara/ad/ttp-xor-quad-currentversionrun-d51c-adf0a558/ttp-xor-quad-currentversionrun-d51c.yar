rule TTP_XOR_QUAD_CurrentVersionRun_d51c {
  strings:
    $key_d51c = { 86 73 [2] a2 7d [2] 89 51 [2] a7 73 [2] b3 68 [2] bc 72 [2] a2 6f [2] a0 6e [2] bb 68 [2] a7 6f [2] bb 40 }

  condition:
    any of them
}