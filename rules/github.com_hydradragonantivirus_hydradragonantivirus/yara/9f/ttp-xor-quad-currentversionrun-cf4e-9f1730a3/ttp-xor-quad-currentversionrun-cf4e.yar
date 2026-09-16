rule TTP_XOR_QUAD_CurrentVersionRun_cf4e {
  strings:
    $key_cf4e = { 9c 21 [2] b8 2f [2] 93 03 [2] bd 21 [2] a9 3a [2] a6 20 [2] b8 3d [2] ba 3c [2] a1 3a [2] bd 3d [2] a1 12 }

  condition:
    any of them
}