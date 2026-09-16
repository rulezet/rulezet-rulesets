rule TTP_XOR_MULT_DOSStub_ca1c {
  strings:
    $key_ca1c = { 9e 74 [2] ea 6c [2] ad 6e [2] ea 7f [2] a4 73 [2] a8 79 [2] bf 72 [2] a4 3c [2] 99 }

  condition:
    any of them
}