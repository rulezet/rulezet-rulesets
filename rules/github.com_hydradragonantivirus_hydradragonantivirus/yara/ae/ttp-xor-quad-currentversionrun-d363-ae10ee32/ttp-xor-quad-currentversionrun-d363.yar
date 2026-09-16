rule TTP_XOR_QUAD_CurrentVersionRun_d363 {
  strings:
    $key_d363 = { 80 0c [2] a4 02 [2] 8f 2e [2] a1 0c [2] b5 17 [2] ba 0d [2] a4 10 [2] a6 11 [2] bd 17 [2] a1 10 [2] bd 3f }

  condition:
    any of them
}