rule TTP_XOR_MULT_DOSStub_cf35 {
  strings:
    $key_cf35 = { 9b 5d [2] ef 45 [2] a8 47 [2] ef 56 [2] a1 5a [2] ad 50 [2] ba 5b [2] a1 15 [2] 9c }

  condition:
    any of them
}