rule TTP_XOR_QUAD_CurrentVersionRun_ca52 {
  strings:
    $key_ca52 = { 99 3d [2] bd 33 [2] 96 1f [2] b8 3d [2] ac 26 [2] a3 3c [2] bd 21 [2] bf 20 [2] a4 26 [2] b8 21 [2] a4 0e }

  condition:
    any of them
}