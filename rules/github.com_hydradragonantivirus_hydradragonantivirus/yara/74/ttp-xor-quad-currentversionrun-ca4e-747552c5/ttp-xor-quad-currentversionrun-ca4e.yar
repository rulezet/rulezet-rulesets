rule TTP_XOR_QUAD_CurrentVersionRun_ca4e {
  strings:
    $key_ca4e = { 99 21 [2] bd 2f [2] 96 03 [2] b8 21 [2] ac 3a [2] a3 20 [2] bd 3d [2] bf 3c [2] a4 3a [2] b8 3d [2] a4 12 }

  condition:
    any of them
}