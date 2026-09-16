rule TTP_XOR_QUAD_CurrentVersionRun_d3c2 {
  strings:
    $key_d3c2 = { 80 ad [2] a4 a3 [2] 8f 8f [2] a1 ad [2] b5 b6 [2] ba ac [2] a4 b1 [2] a6 b0 [2] bd b6 [2] a1 b1 [2] bd 9e }

  condition:
    any of them
}