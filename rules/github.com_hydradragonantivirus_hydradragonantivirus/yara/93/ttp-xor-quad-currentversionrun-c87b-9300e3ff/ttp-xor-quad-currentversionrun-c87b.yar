rule TTP_XOR_QUAD_CurrentVersionRun_c87b {
  strings:
    $key_c87b = { 9b 14 [2] bf 1a [2] 94 36 [2] ba 14 [2] ae 0f [2] a1 15 [2] bf 08 [2] bd 09 [2] a6 0f [2] ba 08 [2] a6 27 }

  condition:
    any of them
}