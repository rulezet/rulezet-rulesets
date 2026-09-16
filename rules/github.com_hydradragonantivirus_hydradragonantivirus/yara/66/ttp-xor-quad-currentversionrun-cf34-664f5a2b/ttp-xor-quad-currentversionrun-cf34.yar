rule TTP_XOR_QUAD_CurrentVersionRun_cf34 {
  strings:
    $key_cf34 = { 9c 5b [2] b8 55 [2] 93 79 [2] bd 5b [2] a9 40 [2] a6 5a [2] b8 47 [2] ba 46 [2] a1 40 [2] bd 47 [2] a1 68 }

  condition:
    any of them
}