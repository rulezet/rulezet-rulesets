rule TTP_XOR_QUAD_CurrentVersionRun_c9ad {
  strings:
    $key_c9ad = { 9a c2 [2] be cc [2] 95 e0 [2] bb c2 [2] af d9 [2] a0 c3 [2] be de [2] bc df [2] a7 d9 [2] bb de [2] a7 f1 }

  condition:
    any of them
}