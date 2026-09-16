rule TTP_XOR_MULT_DOSStub_cfa8 {
  strings:
    $key_cfa8 = { 9b c0 [2] ef d8 [2] a8 da [2] ef cb [2] a1 c7 [2] ad cd [2] ba c6 [2] a1 88 [2] 9c }

  condition:
    any of them
}