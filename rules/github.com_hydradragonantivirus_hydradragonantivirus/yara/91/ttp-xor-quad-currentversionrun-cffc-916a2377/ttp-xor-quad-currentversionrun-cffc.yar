rule TTP_XOR_QUAD_CurrentVersionRun_cffc {
  strings:
    $key_cffc = { 9c 93 [2] b8 9d [2] 93 b1 [2] bd 93 [2] a9 88 [2] a6 92 [2] b8 8f [2] ba 8e [2] a1 88 [2] bd 8f [2] a1 a0 }

  condition:
    any of them
}