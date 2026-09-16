rule TTP_XOR_MULT_DOSStub_cf01 {
  strings:
    $key_cf01 = { 9b 69 [2] ef 71 [2] a8 73 [2] ef 62 [2] a1 6e [2] ad 64 [2] ba 6f [2] a1 21 [2] 9c }

  condition:
    any of them
}