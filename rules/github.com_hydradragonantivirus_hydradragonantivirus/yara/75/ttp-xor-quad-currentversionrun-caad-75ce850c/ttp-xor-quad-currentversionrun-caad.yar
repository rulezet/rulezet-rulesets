rule TTP_XOR_QUAD_CurrentVersionRun_caad {
  strings:
    $key_caad = { 99 c2 [2] bd cc [2] 96 e0 [2] b8 c2 [2] ac d9 [2] a3 c3 [2] bd de [2] bf df [2] a4 d9 [2] b8 de [2] a4 f1 }

  condition:
    any of them
}