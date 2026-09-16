rule TTP_XOR_QUAD_CurrentVersionRun_cdb6 {
  strings:
    $key_cdb6 = { 9e d9 [2] ba d7 [2] 91 fb [2] bf d9 [2] ab c2 [2] a4 d8 [2] ba c5 [2] b8 c4 [2] a3 c2 [2] bf c5 [2] a3 ea }

  condition:
    any of them
}