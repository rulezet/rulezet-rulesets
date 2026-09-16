rule TTP_XOR_QUAD_CurrentVersionRun_d3a6 {
  strings:
    $key_d3a6 = { 80 c9 [2] a4 c7 [2] 8f eb [2] a1 c9 [2] b5 d2 [2] ba c8 [2] a4 d5 [2] a6 d4 [2] bd d2 [2] a1 d5 [2] bd fa }

  condition:
    any of them
}