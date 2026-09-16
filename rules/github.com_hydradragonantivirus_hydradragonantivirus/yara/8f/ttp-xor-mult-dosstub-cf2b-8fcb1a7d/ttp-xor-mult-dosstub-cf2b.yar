rule TTP_XOR_MULT_DOSStub_cf2b {
  strings:
    $key_cf2b = { 9b 43 [2] ef 5b [2] a8 59 [2] ef 48 [2] a1 44 [2] ad 4e [2] ba 45 [2] a1 0b [2] 9c }

  condition:
    any of them
}