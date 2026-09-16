rule TTP_XOR_QUAD_CurrentVersionRun_d452 {
  strings:
    $key_d452 = { 87 3d [2] a3 33 [2] 88 1f [2] a6 3d [2] b2 26 [2] bd 3c [2] a3 21 [2] a1 20 [2] ba 26 [2] a6 21 [2] ba 0e }

  condition:
    any of them
}