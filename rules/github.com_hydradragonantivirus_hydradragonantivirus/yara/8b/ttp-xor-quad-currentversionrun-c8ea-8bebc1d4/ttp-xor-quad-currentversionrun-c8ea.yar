rule TTP_XOR_QUAD_CurrentVersionRun_c8ea {
  strings:
    $key_c8ea = { 9b 85 [2] bf 8b [2] 94 a7 [2] ba 85 [2] ae 9e [2] a1 84 [2] bf 99 [2] bd 98 [2] a6 9e [2] ba 99 [2] a6 b6 }

  condition:
    any of them
}