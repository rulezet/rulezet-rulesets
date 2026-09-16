rule TTP_XOR_MULT_DOSStub_cf71 {
  strings:
    $key_cf71 = { 9b 19 [2] ef 01 [2] a8 03 [2] ef 12 [2] a1 1e [2] ad 14 [2] ba 1f [2] a1 51 [2] 9c }

  condition:
    any of them
}