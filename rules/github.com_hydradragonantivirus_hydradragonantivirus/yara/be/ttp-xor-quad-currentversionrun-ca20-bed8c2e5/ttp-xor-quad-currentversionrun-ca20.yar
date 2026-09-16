rule TTP_XOR_QUAD_CurrentVersionRun_ca20 {
  strings:
    $key_ca20 = { 99 4f [2] bd 41 [2] 96 6d [2] b8 4f [2] ac 54 [2] a3 4e [2] bd 53 [2] bf 52 [2] a4 54 [2] b8 53 [2] a4 7c }

  condition:
    any of them
}