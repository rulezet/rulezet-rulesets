rule TTP_XOR_QUAD_CurrentVersionRun_c8ac {
  strings:
    $key_c8ac = { 9b c3 [2] bf cd [2] 94 e1 [2] ba c3 [2] ae d8 [2] a1 c2 [2] bf df [2] bd de [2] a6 d8 [2] ba df [2] a6 f0 }

  condition:
    any of them
}