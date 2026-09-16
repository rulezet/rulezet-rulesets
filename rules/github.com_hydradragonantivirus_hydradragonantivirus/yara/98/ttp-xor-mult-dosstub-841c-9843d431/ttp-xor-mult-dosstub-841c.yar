rule TTP_XOR_MULT_DOSStub_841c {
  strings:
    $key_841c = { d0 74 [2] a4 6c [2] e3 6e [2] a4 7f [2] ea 73 [2] e6 79 [2] f1 72 [2] ea 3c [2] d7 }

  condition:
    any of them
}