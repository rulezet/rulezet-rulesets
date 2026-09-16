rule TTP_XOR_QUAD_CurrentVersionRun_cf77 {
  strings:
    $key_cf77 = { 9c 18 [2] b8 16 [2] 93 3a [2] bd 18 [2] a9 03 [2] a6 19 [2] b8 04 [2] ba 05 [2] a1 03 [2] bd 04 [2] a1 2b }

  condition:
    any of them
}