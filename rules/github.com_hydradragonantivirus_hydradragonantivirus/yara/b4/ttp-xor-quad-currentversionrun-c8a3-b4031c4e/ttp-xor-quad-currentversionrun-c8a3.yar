rule TTP_XOR_QUAD_CurrentVersionRun_c8a3 {
  strings:
    $key_c8a3 = { 9b cc [2] bf c2 [2] 94 ee [2] ba cc [2] ae d7 [2] a1 cd [2] bf d0 [2] bd d1 [2] a6 d7 [2] ba d0 [2] a6 ff }

  condition:
    any of them
}