rule TTP_XOR_QUAD_CurrentVersionRun_ca40 {
  strings:
    $key_ca40 = { 99 2f [2] bd 21 [2] 96 0d [2] b8 2f [2] ac 34 [2] a3 2e [2] bd 33 [2] bf 32 [2] a4 34 [2] b8 33 [2] a4 1c }

  condition:
    any of them
}