rule TTP_XOR_MULT_DOSStub_cf0c {
  strings:
    $key_cf0c = { 9b 64 [2] ef 7c [2] a8 7e [2] ef 6f [2] a1 63 [2] ad 69 [2] ba 62 [2] a1 2c [2] 9c }

  condition:
    any of them
}