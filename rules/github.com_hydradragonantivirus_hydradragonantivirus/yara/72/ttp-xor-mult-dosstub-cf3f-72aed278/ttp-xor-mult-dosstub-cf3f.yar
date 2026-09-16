rule TTP_XOR_MULT_DOSStub_cf3f {
  strings:
    $key_cf3f = { 9b 57 [2] ef 4f [2] a8 4d [2] ef 5c [2] a1 50 [2] ad 5a [2] ba 51 [2] a1 1f [2] 9c }

  condition:
    any of them
}