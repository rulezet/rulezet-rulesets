rule TTP_XOR_QUAD_CurrentVersionRun_d5ec {
  strings:
    $key_d5ec = { 86 83 [2] a2 8d [2] 89 a1 [2] a7 83 [2] b3 98 [2] bc 82 [2] a2 9f [2] a0 9e [2] bb 98 [2] a7 9f [2] bb b0 }

  condition:
    any of them
}