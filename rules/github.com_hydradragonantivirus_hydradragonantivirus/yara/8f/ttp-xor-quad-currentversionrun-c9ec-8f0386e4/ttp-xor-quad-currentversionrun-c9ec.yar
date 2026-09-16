rule TTP_XOR_QUAD_CurrentVersionRun_c9ec {
  strings:
    $key_c9ec = { 9a 83 [2] be 8d [2] 95 a1 [2] bb 83 [2] af 98 [2] a0 82 [2] be 9f [2] bc 9e [2] a7 98 [2] bb 9f [2] a7 b0 }

  condition:
    any of them
}