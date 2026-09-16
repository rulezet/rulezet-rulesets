rule TTP_XOR_QUAD_CurrentVersionRun_c84a {
  strings:
    $key_c84a = { 9b 25 [2] bf 2b [2] 94 07 [2] ba 25 [2] ae 3e [2] a1 24 [2] bf 39 [2] bd 38 [2] a6 3e [2] ba 39 [2] a6 16 }

  condition:
    any of them
}