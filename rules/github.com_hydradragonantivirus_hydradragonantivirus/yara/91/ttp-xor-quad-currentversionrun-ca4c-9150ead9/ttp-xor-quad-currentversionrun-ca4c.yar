rule TTP_XOR_QUAD_CurrentVersionRun_ca4c {
  strings:
    $key_ca4c = { 99 23 [2] bd 2d [2] 96 01 [2] b8 23 [2] ac 38 [2] a3 22 [2] bd 3f [2] bf 3e [2] a4 38 [2] b8 3f [2] a4 10 }

  condition:
    any of them
}