rule TTP_XOR_QUAD_CurrentVersionRun_d448 {
  strings:
    $key_d448 = { 87 27 [2] a3 29 [2] 88 05 [2] a6 27 [2] b2 3c [2] bd 26 [2] a3 3b [2] a1 3a [2] ba 3c [2] a6 3b [2] ba 14 }

  condition:
    any of them
}