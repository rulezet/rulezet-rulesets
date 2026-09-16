rule TTP_XOR_QUAD_CurrentVersionRun_d37c {
  strings:
    $key_d37c = { 80 13 [2] a4 1d [2] 8f 31 [2] a1 13 [2] b5 08 [2] ba 12 [2] a4 0f [2] a6 0e [2] bd 08 [2] a1 0f [2] bd 20 }

  condition:
    any of them
}