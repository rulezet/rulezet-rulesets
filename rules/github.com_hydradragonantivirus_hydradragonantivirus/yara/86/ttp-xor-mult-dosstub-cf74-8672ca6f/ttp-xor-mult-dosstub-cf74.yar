rule TTP_XOR_MULT_DOSStub_cf74 {
  strings:
    $key_cf74 = { 9b 1c [2] ef 04 [2] a8 06 [2] ef 17 [2] a1 1b [2] ad 11 [2] ba 1a [2] a1 54 [2] 9c }

  condition:
    any of them
}