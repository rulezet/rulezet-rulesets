rule TTP_XOR_QUAD_CurrentVersionRun_ca7a {
  strings:
    $key_ca7a = { 99 15 [2] bd 1b [2] 96 37 [2] b8 15 [2] ac 0e [2] a3 14 [2] bd 09 [2] bf 08 [2] a4 0e [2] b8 09 [2] a4 26 }

  condition:
    any of them
}