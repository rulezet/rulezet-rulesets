rule TTP_XOR_QUAD_CurrentVersionRun_d3c1 {
  strings:
    $key_d3c1 = { 80 ae [2] a4 a0 [2] 8f 8c [2] a1 ae [2] b5 b5 [2] ba af [2] a4 b2 [2] a6 b3 [2] bd b5 [2] a1 b2 [2] bd 9d }

  condition:
    any of them
}