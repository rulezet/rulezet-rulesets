rule TTP_XOR_QUAD_CurrentVersionRun_c8eb {
  strings:
    $key_c8eb = { 9b 84 [2] bf 8a [2] 94 a6 [2] ba 84 [2] ae 9f [2] a1 85 [2] bf 98 [2] bd 99 [2] a6 9f [2] ba 98 [2] a6 b7 }

  condition:
    any of them
}