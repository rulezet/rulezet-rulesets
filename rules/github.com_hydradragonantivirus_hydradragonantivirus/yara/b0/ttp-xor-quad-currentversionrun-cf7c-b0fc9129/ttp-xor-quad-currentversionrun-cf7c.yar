rule TTP_XOR_QUAD_CurrentVersionRun_cf7c {
  strings:
    $key_cf7c = { 9c 13 [2] b8 1d [2] 93 31 [2] bd 13 [2] a9 08 [2] a6 12 [2] b8 0f [2] ba 0e [2] a1 08 [2] bd 0f [2] a1 20 }

  condition:
    any of them
}