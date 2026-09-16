rule TTP_XOR_QUAD_CurrentVersionRun_ca5f {
  strings:
    $key_ca5f = { 99 30 [2] bd 3e [2] 96 12 [2] b8 30 [2] ac 2b [2] a3 31 [2] bd 2c [2] bf 2d [2] a4 2b [2] b8 2c [2] a4 03 }

  condition:
    any of them
}