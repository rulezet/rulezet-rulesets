rule TTP_XOR_QUAD_CurrentVersionRun_cf07 {
  strings:
    $key_cf07 = { 9c 68 [2] b8 66 [2] 93 4a [2] bd 68 [2] a9 73 [2] a6 69 [2] b8 74 [2] ba 75 [2] a1 73 [2] bd 74 [2] a1 5b }

  condition:
    any of them
}