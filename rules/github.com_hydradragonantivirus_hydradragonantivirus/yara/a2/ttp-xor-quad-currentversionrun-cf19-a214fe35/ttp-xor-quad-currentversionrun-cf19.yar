rule TTP_XOR_QUAD_CurrentVersionRun_cf19 {
  strings:
    $key_cf19 = { 9c 76 [2] b8 78 [2] 93 54 [2] bd 76 [2] a9 6d [2] a6 77 [2] b8 6a [2] ba 6b [2] a1 6d [2] bd 6a [2] a1 45 }

  condition:
    any of them
}