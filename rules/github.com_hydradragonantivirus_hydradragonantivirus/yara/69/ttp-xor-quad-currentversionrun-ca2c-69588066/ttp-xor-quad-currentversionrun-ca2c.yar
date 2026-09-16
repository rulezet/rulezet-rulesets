rule TTP_XOR_QUAD_CurrentVersionRun_ca2c {
  strings:
    $key_ca2c = { 99 43 [2] bd 4d [2] 96 61 [2] b8 43 [2] ac 58 [2] a3 42 [2] bd 5f [2] bf 5e [2] a4 58 [2] b8 5f [2] a4 70 }

  condition:
    any of them
}