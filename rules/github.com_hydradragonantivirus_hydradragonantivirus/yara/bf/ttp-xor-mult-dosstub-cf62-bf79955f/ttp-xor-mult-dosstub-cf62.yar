rule TTP_XOR_MULT_DOSStub_cf62 {
  strings:
    $key_cf62 = { 9b 0a [2] ef 12 [2] a8 10 [2] ef 01 [2] a1 0d [2] ad 07 [2] ba 0c [2] a1 42 [2] 9c }

  condition:
    any of them
}