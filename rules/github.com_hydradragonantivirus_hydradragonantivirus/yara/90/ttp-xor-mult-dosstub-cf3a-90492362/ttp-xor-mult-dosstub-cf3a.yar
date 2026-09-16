rule TTP_XOR_MULT_DOSStub_cf3a {
  strings:
    $key_cf3a = { 9b 52 [2] ef 4a [2] a8 48 [2] ef 59 [2] a1 55 [2] ad 5f [2] ba 54 [2] a1 1a [2] 9c }

  condition:
    any of them
}