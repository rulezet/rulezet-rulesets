rule TTP_XOR_QUAD_CurrentVersionRun_d337 {
  strings:
    $key_d337 = { 80 58 [2] a4 56 [2] 8f 7a [2] a1 58 [2] b5 43 [2] ba 59 [2] a4 44 [2] a6 45 [2] bd 43 [2] a1 44 [2] bd 6b }

  condition:
    any of them
}