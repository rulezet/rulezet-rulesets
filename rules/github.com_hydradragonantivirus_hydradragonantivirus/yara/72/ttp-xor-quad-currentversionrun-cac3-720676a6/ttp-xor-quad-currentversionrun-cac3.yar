rule TTP_XOR_QUAD_CurrentVersionRun_cac3 {
  strings:
    $key_cac3 = { 99 ac [2] bd a2 [2] 96 8e [2] b8 ac [2] ac b7 [2] a3 ad [2] bd b0 [2] bf b1 [2] a4 b7 [2] b8 b0 [2] a4 9f }

  condition:
    any of them
}