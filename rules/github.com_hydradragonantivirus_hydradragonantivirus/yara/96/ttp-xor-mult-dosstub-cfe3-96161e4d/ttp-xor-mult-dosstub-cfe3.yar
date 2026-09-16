rule TTP_XOR_MULT_DOSStub_cfe3 {
  strings:
    $key_cfe3 = { 9b 8b [2] ef 93 [2] a8 91 [2] ef 80 [2] a1 8c [2] ad 86 [2] ba 8d [2] a1 c3 [2] 9c }

  condition:
    any of them
}