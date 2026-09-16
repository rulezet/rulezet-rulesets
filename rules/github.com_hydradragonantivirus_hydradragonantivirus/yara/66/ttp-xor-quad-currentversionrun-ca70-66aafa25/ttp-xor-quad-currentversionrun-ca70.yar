rule TTP_XOR_QUAD_CurrentVersionRun_ca70 {
  strings:
    $key_ca70 = { 99 1f [2] bd 11 [2] 96 3d [2] b8 1f [2] ac 04 [2] a3 1e [2] bd 03 [2] bf 02 [2] a4 04 [2] b8 03 [2] a4 2c }

  condition:
    any of them
}