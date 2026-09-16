rule TTP_XOR_QUAD_CurrentVersionRun_d377 {
  strings:
    $key_d377 = { 80 18 [2] a4 16 [2] 8f 3a [2] a1 18 [2] b5 03 [2] ba 19 [2] a4 04 [2] a6 05 [2] bd 03 [2] a1 04 [2] bd 2b }

  condition:
    any of them
}