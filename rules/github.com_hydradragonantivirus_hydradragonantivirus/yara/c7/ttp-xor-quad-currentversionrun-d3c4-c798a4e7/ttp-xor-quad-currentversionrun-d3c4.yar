rule TTP_XOR_QUAD_CurrentVersionRun_d3c4 {
  strings:
    $key_d3c4 = { 80 ab [2] a4 a5 [2] 8f 89 [2] a1 ab [2] b5 b0 [2] ba aa [2] a4 b7 [2] a6 b6 [2] bd b0 [2] a1 b7 [2] bd 98 }

  condition:
    any of them
}