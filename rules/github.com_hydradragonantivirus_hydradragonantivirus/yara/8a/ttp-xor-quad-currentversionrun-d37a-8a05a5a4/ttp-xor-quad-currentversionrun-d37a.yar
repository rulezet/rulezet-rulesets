rule TTP_XOR_QUAD_CurrentVersionRun_d37a {
  strings:
    $key_d37a = { 80 15 [2] a4 1b [2] 8f 37 [2] a1 15 [2] b5 0e [2] ba 14 [2] a4 09 [2] a6 08 [2] bd 0e [2] a1 09 [2] bd 26 }

  condition:
    any of them
}