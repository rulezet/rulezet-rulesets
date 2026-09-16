rule TTP_XOR_MULT_DOSStub_cffb {
  strings:
    $key_cffb = { 9b 93 [2] ef 8b [2] a8 89 [2] ef 98 [2] a1 94 [2] ad 9e [2] ba 95 [2] a1 db [2] 9c }

  condition:
    any of them
}