rule TTP_XOR_QUAD_CurrentVersionRun_cf49 {
  strings:
    $key_cf49 = { 9c 26 [2] b8 28 [2] 93 04 [2] bd 26 [2] a9 3d [2] a6 27 [2] b8 3a [2] ba 3b [2] a1 3d [2] bd 3a [2] a1 15 }

  condition:
    any of them
}