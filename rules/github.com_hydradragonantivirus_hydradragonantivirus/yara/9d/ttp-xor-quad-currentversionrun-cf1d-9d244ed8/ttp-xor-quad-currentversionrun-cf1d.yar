rule TTP_XOR_QUAD_CurrentVersionRun_cf1d {
  strings:
    $key_cf1d = { 9c 72 [2] b8 7c [2] 93 50 [2] bd 72 [2] a9 69 [2] a6 73 [2] b8 6e [2] ba 6f [2] a1 69 [2] bd 6e [2] a1 41 }

  condition:
    any of them
}