rule TTP_XOR_QUAD_CurrentVersionRun_cf45 {
  strings:
    $key_cf45 = { 9c 2a [2] b8 24 [2] 93 08 [2] bd 2a [2] a9 31 [2] a6 2b [2] b8 36 [2] ba 37 [2] a1 31 [2] bd 36 [2] a1 19 }

  condition:
    any of them
}