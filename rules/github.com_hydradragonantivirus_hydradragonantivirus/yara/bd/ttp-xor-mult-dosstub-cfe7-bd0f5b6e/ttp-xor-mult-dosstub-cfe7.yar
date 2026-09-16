rule TTP_XOR_MULT_DOSStub_cfe7 {
  strings:
    $key_cfe7 = { 9b 8f [2] ef 97 [2] a8 95 [2] ef 84 [2] a1 88 [2] ad 82 [2] ba 89 [2] a1 c7 [2] 9c }

  condition:
    any of them
}