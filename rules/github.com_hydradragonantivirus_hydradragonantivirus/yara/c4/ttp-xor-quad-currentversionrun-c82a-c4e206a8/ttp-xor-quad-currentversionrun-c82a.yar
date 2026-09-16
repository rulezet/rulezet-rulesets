rule TTP_XOR_QUAD_CurrentVersionRun_c82a {
  strings:
    $key_c82a = { 9b 45 [2] bf 4b [2] 94 67 [2] ba 45 [2] ae 5e [2] a1 44 [2] bf 59 [2] bd 58 [2] a6 5e [2] ba 59 [2] a6 76 }

  condition:
    any of them
}