rule TTP_XOR_QUAD_CurrentVersionRun_d3b7 {
  strings:
    $key_d3b7 = { 80 d8 [2] a4 d6 [2] 8f fa [2] a1 d8 [2] b5 c3 [2] ba d9 [2] a4 c4 [2] a6 c5 [2] bd c3 [2] a1 c4 [2] bd eb }

  condition:
    any of them
}