rule TTP_XOR_QUAD_CurrentVersionRun_c9c9 {
  strings:
    $key_c9c9 = { 9a a6 [2] be a8 [2] 95 84 [2] bb a6 [2] af bd [2] a0 a7 [2] be ba [2] bc bb [2] a7 bd [2] bb ba [2] a7 95 }

  condition:
    any of them
}