rule TTP_XOR_MULT_DOSStub_845c {
  strings:
    $key_845c = { d0 34 [2] a4 2c [2] e3 2e [2] a4 3f [2] ea 33 [2] e6 39 [2] f1 32 [2] ea 7c [2] d7 }

  condition:
    any of them
}