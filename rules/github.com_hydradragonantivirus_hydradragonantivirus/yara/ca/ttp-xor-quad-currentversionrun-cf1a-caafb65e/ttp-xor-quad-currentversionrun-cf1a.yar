rule TTP_XOR_QUAD_CurrentVersionRun_cf1a {
  strings:
    $key_cf1a = { 9c 75 [2] b8 7b [2] 93 57 [2] bd 75 [2] a9 6e [2] a6 74 [2] b8 69 [2] ba 68 [2] a1 6e [2] bd 69 [2] a1 46 }

  condition:
    any of them
}