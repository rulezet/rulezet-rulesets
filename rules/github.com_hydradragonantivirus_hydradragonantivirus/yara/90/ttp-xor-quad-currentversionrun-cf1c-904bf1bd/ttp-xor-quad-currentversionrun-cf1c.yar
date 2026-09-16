rule TTP_XOR_QUAD_CurrentVersionRun_cf1c {
  strings:
    $key_cf1c = { 9c 73 [2] b8 7d [2] 93 51 [2] bd 73 [2] a9 68 [2] a6 72 [2] b8 6f [2] ba 6e [2] a1 68 [2] bd 6f [2] a1 40 }

  condition:
    any of them
}