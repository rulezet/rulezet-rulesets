rule TTP_XOR_QUAD_CurrentVersionRun_d34e {
  strings:
    $key_d34e = { 80 21 [2] a4 2f [2] 8f 03 [2] a1 21 [2] b5 3a [2] ba 20 [2] a4 3d [2] a6 3c [2] bd 3a [2] a1 3d [2] bd 12 }

  condition:
    any of them
}