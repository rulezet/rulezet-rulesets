rule TTP_XOR_QUAD_CurrentVersionRun_d21a {
  strings:
    $key_d21a = { 81 75 [2] a5 7b [2] 8e 57 [2] a0 75 [2] b4 6e [2] bb 74 [2] a5 69 [2] a7 68 [2] bc 6e [2] a0 69 [2] bc 46 }

  condition:
    any of them
}