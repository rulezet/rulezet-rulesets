rule TTP_XOR_QUAD_CurrentVersionRun_c9ea {
  strings:
    $key_c9ea = { 9a 85 [2] be 8b [2] 95 a7 [2] bb 85 [2] af 9e [2] a0 84 [2] be 99 [2] bc 98 [2] a7 9e [2] bb 99 [2] a7 b6 }

  condition:
    any of them
}