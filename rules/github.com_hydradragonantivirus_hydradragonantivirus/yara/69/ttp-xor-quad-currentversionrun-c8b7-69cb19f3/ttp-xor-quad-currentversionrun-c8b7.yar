rule TTP_XOR_QUAD_CurrentVersionRun_c8b7 {
  strings:
    $key_c8b7 = { 9b d8 [2] bf d6 [2] 94 fa [2] ba d8 [2] ae c3 [2] a1 d9 [2] bf c4 [2] bd c5 [2] a6 c3 [2] ba c4 [2] a6 eb }

  condition:
    any of them
}