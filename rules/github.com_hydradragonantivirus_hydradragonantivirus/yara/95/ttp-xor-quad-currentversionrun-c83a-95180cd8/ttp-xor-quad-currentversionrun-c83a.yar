rule TTP_XOR_QUAD_CurrentVersionRun_c83a {
  strings:
    $key_c83a = { 9b 55 [2] bf 5b [2] 94 77 [2] ba 55 [2] ae 4e [2] a1 54 [2] bf 49 [2] bd 48 [2] a6 4e [2] ba 49 [2] a6 66 }

  condition:
    any of them
}