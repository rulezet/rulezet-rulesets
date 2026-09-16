rule TTP_XOR_MULT_DOSStub_cf23 {
  strings:
    $key_cf23 = { 9b 4b [2] ef 53 [2] a8 51 [2] ef 40 [2] a1 4c [2] ad 46 [2] ba 4d [2] a1 03 [2] 9c }

  condition:
    any of them
}