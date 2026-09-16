rule TTP_XOR_QUAD_CurrentVersionRun_c803 {
  strings:
    $key_c803 = { 9b 6c [2] bf 62 [2] 94 4e [2] ba 6c [2] ae 77 [2] a1 6d [2] bf 70 [2] bd 71 [2] a6 77 [2] ba 70 [2] a6 5f }

  condition:
    any of them
}