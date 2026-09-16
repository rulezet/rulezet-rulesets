rule TTP_XOR_QUAD_CurrentVersionRun_cfeb {
  strings:
    $key_cfeb = { 9c 84 [2] b8 8a [2] 93 a6 [2] bd 84 [2] a9 9f [2] a6 85 [2] b8 98 [2] ba 99 [2] a1 9f [2] bd 98 [2] a1 b7 }

  condition:
    any of them
}