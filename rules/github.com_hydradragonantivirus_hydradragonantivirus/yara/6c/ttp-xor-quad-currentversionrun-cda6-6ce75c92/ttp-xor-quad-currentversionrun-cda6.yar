rule TTP_XOR_QUAD_CurrentVersionRun_cda6 {
  strings:
    $key_cda6 = { 9e c9 [2] ba c7 [2] 91 eb [2] bf c9 [2] ab d2 [2] a4 c8 [2] ba d5 [2] b8 d4 [2] a3 d2 [2] bf d5 [2] a3 fa }

  condition:
    any of them
}