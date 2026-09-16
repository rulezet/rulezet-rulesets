rule TTP_XOR_QUAD_CurrentVersionRun_cdba {
  strings:
    $key_cdba = { 9e d5 [2] ba db [2] 91 f7 [2] bf d5 [2] ab ce [2] a4 d4 [2] ba c9 [2] b8 c8 [2] a3 ce [2] bf c9 [2] a3 e6 }

  condition:
    any of them
}