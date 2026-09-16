rule TTP_XOR_QUAD_CurrentVersionRun_c816 {
  strings:
    $key_c816 = { 9b 79 [2] bf 77 [2] 94 5b [2] ba 79 [2] ae 62 [2] a1 78 [2] bf 65 [2] bd 64 [2] a6 62 [2] ba 65 [2] a6 4a }

  condition:
    any of them
}