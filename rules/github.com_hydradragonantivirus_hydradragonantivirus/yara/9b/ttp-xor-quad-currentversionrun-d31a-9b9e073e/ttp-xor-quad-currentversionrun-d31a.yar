rule TTP_XOR_QUAD_CurrentVersionRun_d31a {
  strings:
    $key_d31a = { 80 75 [2] a4 7b [2] 8f 57 [2] a1 75 [2] b5 6e [2] ba 74 [2] a4 69 [2] a6 68 [2] bd 6e [2] a1 69 [2] bd 46 }

  condition:
    any of them
}