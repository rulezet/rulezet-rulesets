rule TTP_XOR_QUAD_CurrentVersionRun_d407 {
  strings:
    $key_d407 = { 87 68 [2] a3 66 [2] 88 4a [2] a6 68 [2] b2 73 [2] bd 69 [2] a3 74 [2] a1 75 [2] ba 73 [2] a6 74 [2] ba 5b }

  condition:
    any of them
}