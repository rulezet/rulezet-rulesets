rule TTP_XOR_QUAD_CurrentVersionRun_c865 {
  strings:
    $key_c865 = { 9b 0a [2] bf 04 [2] 94 28 [2] ba 0a [2] ae 11 [2] a1 0b [2] bf 16 [2] bd 17 [2] a6 11 [2] ba 16 [2] a6 39 }

  condition:
    any of them
}