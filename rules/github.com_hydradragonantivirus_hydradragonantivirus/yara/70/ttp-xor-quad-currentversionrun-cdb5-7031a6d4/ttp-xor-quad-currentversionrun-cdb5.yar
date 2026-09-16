rule TTP_XOR_QUAD_CurrentVersionRun_cdb5 {
  strings:
    $key_cdb5 = { 9e da [2] ba d4 [2] 91 f8 [2] bf da [2] ab c1 [2] a4 db [2] ba c6 [2] b8 c7 [2] a3 c1 [2] bf c6 [2] a3 e9 }

  condition:
    any of them
}