rule TTP_XOR_QUAD_CurrentVersionRun_ca2d {
  strings:
    $key_ca2d = { 99 42 [2] bd 4c [2] 96 60 [2] b8 42 [2] ac 59 [2] a3 43 [2] bd 5e [2] bf 5f [2] a4 59 [2] b8 5e [2] a4 71 }

  condition:
    any of them
}