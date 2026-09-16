rule TTP_XOR_QUAD_CurrentVersionRun_d3d8 {
  strings:
    $key_d3d8 = { 80 b7 [2] a4 b9 [2] 8f 95 [2] a1 b7 [2] b5 ac [2] ba b6 [2] a4 ab [2] a6 aa [2] bd ac [2] a1 ab [2] bd 84 }

  condition:
    any of them
}