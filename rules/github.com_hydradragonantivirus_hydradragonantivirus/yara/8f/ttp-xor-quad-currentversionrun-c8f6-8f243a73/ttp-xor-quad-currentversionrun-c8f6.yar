rule TTP_XOR_QUAD_CurrentVersionRun_c8f6 {
  strings:
    $key_c8f6 = { 9b 99 [2] bf 97 [2] 94 bb [2] ba 99 [2] ae 82 [2] a1 98 [2] bf 85 [2] bd 84 [2] a6 82 [2] ba 85 [2] a6 aa }

  condition:
    any of them
}