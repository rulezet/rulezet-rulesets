rule TTP_XOR_QUAD_CurrentVersionRun_ca1d {
  strings:
    $key_ca1d = { 99 72 [2] bd 7c [2] 96 50 [2] b8 72 [2] ac 69 [2] a3 73 [2] bd 6e [2] bf 6f [2] a4 69 [2] b8 6e [2] a4 41 }

  condition:
    any of them
}