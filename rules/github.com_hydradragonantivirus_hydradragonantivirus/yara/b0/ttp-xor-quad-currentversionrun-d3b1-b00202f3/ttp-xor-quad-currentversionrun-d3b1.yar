rule TTP_XOR_QUAD_CurrentVersionRun_d3b1 {
  strings:
    $key_d3b1 = { 80 de [2] a4 d0 [2] 8f fc [2] a1 de [2] b5 c5 [2] ba df [2] a4 c2 [2] a6 c3 [2] bd c5 [2] a1 c2 [2] bd ed }

  condition:
    any of them
}