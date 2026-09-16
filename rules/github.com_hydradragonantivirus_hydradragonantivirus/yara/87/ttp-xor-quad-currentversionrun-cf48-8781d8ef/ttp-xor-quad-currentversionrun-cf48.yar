rule TTP_XOR_QUAD_CurrentVersionRun_cf48 {
  strings:
    $key_cf48 = { 9c 27 [2] b8 29 [2] 93 05 [2] bd 27 [2] a9 3c [2] a6 26 [2] b8 3b [2] ba 3a [2] a1 3c [2] bd 3b [2] a1 14 }

  condition:
    any of them
}