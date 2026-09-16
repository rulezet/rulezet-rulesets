rule TTP_XOR_MULT_DOSStub_cfe5 {
  strings:
    $key_cfe5 = { 9b 8d [2] ef 95 [2] a8 97 [2] ef 86 [2] a1 8a [2] ad 80 [2] ba 8b [2] a1 c5 [2] 9c }

  condition:
    any of them
}