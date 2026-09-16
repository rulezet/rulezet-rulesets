rule TTP_XOR_MULT_DOSStub_cfeb {
  strings:
    $key_cfeb = { 9b 83 [2] ef 9b [2] a8 99 [2] ef 88 [2] a1 84 [2] ad 8e [2] ba 85 [2] a1 cb [2] 9c }

  condition:
    any of them
}