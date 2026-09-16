rule TTP_XOR_QUAD_CurrentVersionRun_c9cf {
  strings:
    $key_c9cf = { 9a a0 [2] be ae [2] 95 82 [2] bb a0 [2] af bb [2] a0 a1 [2] be bc [2] bc bd [2] a7 bb [2] bb bc [2] a7 93 }

  condition:
    any of them
}