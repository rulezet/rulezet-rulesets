rule TTP_XOR_QUAD_CurrentVersionRun_d348 {
  strings:
    $key_d348 = { 80 27 [2] a4 29 [2] 8f 05 [2] a1 27 [2] b5 3c [2] ba 26 [2] a4 3b [2] a6 3a [2] bd 3c [2] a1 3b [2] bd 14 }

  condition:
    any of them
}