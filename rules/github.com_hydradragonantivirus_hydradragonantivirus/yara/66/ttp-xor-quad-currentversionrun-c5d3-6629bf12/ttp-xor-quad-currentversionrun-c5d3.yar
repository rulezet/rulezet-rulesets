rule TTP_XOR_QUAD_CurrentVersionRun_c5d3 {
  strings:
    $key_c5d3 = { 96 bc [2] b2 b2 [2] 99 9e [2] b7 bc [2] a3 a7 [2] ac bd [2] b2 a0 [2] b0 a1 [2] ab a7 [2] b7 a0 [2] ab 8f }

  condition:
    any of them
}