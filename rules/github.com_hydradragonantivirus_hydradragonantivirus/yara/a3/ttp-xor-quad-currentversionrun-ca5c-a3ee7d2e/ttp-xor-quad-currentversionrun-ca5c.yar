rule TTP_XOR_QUAD_CurrentVersionRun_ca5c {
  strings:
    $key_ca5c = { 99 33 [2] bd 3d [2] 96 11 [2] b8 33 [2] ac 28 [2] a3 32 [2] bd 2f [2] bf 2e [2] a4 28 [2] b8 2f [2] a4 00 }

  condition:
    any of them
}