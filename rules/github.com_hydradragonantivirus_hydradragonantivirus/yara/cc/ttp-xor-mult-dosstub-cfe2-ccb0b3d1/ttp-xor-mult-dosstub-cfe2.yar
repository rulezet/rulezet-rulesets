rule TTP_XOR_MULT_DOSStub_cfe2 {
  strings:
    $key_cfe2 = { 9b 8a [2] ef 92 [2] a8 90 [2] ef 81 [2] a1 8d [2] ad 87 [2] ba 8c [2] a1 c2 [2] 9c }

  condition:
    any of them
}