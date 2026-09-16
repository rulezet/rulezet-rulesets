rule TTP_XOR_MULT_DOSStub_cf2f {
  strings:
    $key_cf2f = { 9b 47 [2] ef 5f [2] a8 5d [2] ef 4c [2] a1 40 [2] ad 4a [2] ba 41 [2] a1 0f [2] 9c }

  condition:
    any of them
}