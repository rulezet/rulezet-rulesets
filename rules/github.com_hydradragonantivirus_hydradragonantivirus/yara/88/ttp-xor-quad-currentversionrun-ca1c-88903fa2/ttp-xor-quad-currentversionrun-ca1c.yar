rule TTP_XOR_QUAD_CurrentVersionRun_ca1c {
  strings:
    $key_ca1c = { 99 73 [2] bd 7d [2] 96 51 [2] b8 73 [2] ac 68 [2] a3 72 [2] bd 6f [2] bf 6e [2] a4 68 [2] b8 6f [2] a4 40 }

  condition:
    any of them
}