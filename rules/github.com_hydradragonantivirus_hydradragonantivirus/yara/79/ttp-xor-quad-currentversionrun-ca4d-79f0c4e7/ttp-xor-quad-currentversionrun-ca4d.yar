rule TTP_XOR_QUAD_CurrentVersionRun_ca4d {
  strings:
    $key_ca4d = { 99 22 [2] bd 2c [2] 96 00 [2] b8 22 [2] ac 39 [2] a3 23 [2] bd 3e [2] bf 3f [2] a4 39 [2] b8 3e [2] a4 11 }

  condition:
    any of them
}