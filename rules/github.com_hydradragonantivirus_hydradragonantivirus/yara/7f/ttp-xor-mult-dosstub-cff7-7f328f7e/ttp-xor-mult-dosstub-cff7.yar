rule TTP_XOR_MULT_DOSStub_cff7 {
  strings:
    $key_cff7 = { 9b 9f [2] ef 87 [2] a8 85 [2] ef 94 [2] a1 98 [2] ad 92 [2] ba 99 [2] a1 d7 [2] 9c }

  condition:
    any of them
}