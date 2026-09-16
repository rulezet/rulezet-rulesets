rule TTP_XOR_QUAD_CurrentVersionRun_ca73 {
  strings:
    $key_ca73 = { 99 1c [2] bd 12 [2] 96 3e [2] b8 1c [2] ac 07 [2] a3 1d [2] bd 00 [2] bf 01 [2] a4 07 [2] b8 00 [2] a4 2f }

  condition:
    any of them
}