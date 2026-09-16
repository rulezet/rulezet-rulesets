rule TTP_XOR_MULT_DOSStub_cf0a {
  strings:
    $key_cf0a = { 9b 62 [2] ef 7a [2] a8 78 [2] ef 69 [2] a1 65 [2] ad 6f [2] ba 64 [2] a1 2a [2] 9c }

  condition:
    any of them
}