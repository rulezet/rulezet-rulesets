rule TTP_XOR_MULT_DOSStub_cf69 {
  strings:
    $key_cf69 = { 9b 01 [2] ef 19 [2] a8 1b [2] ef 0a [2] a1 06 [2] ad 0c [2] ba 07 [2] a1 49 [2] 9c }

  condition:
    any of them
}