rule TTP_XOR_QUAD_CurrentVersionRun_d355 {
  strings:
    $key_d355 = { 80 3a [2] a4 34 [2] 8f 18 [2] a1 3a [2] b5 21 [2] ba 3b [2] a4 26 [2] a6 27 [2] bd 21 [2] a1 26 [2] bd 09 }

  condition:
    any of them
}