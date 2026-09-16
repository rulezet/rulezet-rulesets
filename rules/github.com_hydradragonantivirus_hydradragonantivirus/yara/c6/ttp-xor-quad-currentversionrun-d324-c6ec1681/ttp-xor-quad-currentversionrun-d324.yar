rule TTP_XOR_QUAD_CurrentVersionRun_d324 {
  strings:
    $key_d324 = { 80 4b [2] a4 45 [2] 8f 69 [2] a1 4b [2] b5 50 [2] ba 4a [2] a4 57 [2] a6 56 [2] bd 50 [2] a1 57 [2] bd 78 }

  condition:
    any of them
}