rule TTP_XOR_QUAD_CurrentVersionRun_d304 {
  strings:
    $key_d304 = { 80 6b [2] a4 65 [2] 8f 49 [2] a1 6b [2] b5 70 [2] ba 6a [2] a4 77 [2] a6 76 [2] bd 70 [2] a1 77 [2] bd 58 }

  condition:
    any of them
}