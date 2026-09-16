rule TTP_XOR_QUAD_CurrentVersionRun_c88a {
  strings:
    $key_c88a = { 9b e5 [2] bf eb [2] 94 c7 [2] ba e5 [2] ae fe [2] a1 e4 [2] bf f9 [2] bd f8 [2] a6 fe [2] ba f9 [2] a6 d6 }

  condition:
    any of them
}