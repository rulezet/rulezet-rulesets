rule TTP_XOR_QUAD_CurrentVersionRun_c88c {
  strings:
    $key_c88c = { 9b e3 [2] bf ed [2] 94 c1 [2] ba e3 [2] ae f8 [2] a1 e2 [2] bf ff [2] bd fe [2] a6 f8 [2] ba ff [2] a6 d0 }

  condition:
    any of them
}