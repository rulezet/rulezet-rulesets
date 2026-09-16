rule TTP_XOR_MULT_DOSStub_cf22 {
  strings:
    $key_cf22 = { 9b 4a [2] ef 52 [2] a8 50 [2] ef 41 [2] a1 4d [2] ad 47 [2] ba 4c [2] a1 02 [2] 9c }

  condition:
    any of them
}