rule TTP_XOR_QUAD_CurrentVersionRun_cffd {
  strings:
    $key_cffd = { 9c 92 [2] b8 9c [2] 93 b0 [2] bd 92 [2] a9 89 [2] a6 93 [2] b8 8e [2] ba 8f [2] a1 89 [2] bd 8e [2] a1 a1 }

  condition:
    any of them
}