rule TTP_XOR_QUAD_CurrentVersionRun_c87a {
  strings:
    $key_c87a = { 9b 15 [2] bf 1b [2] 94 37 [2] ba 15 [2] ae 0e [2] a1 14 [2] bf 09 [2] bd 08 [2] a6 0e [2] ba 09 [2] a6 26 }

  condition:
    any of them
}