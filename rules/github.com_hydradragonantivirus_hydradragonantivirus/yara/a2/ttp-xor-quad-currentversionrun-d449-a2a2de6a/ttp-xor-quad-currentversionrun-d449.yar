rule TTP_XOR_QUAD_CurrentVersionRun_d449 {
  strings:
    $key_d449 = { 87 26 [2] a3 28 [2] 88 04 [2] a6 26 [2] b2 3d [2] bd 27 [2] a3 3a [2] a1 3b [2] ba 3d [2] a6 3a [2] ba 15 }

  condition:
    any of them
}