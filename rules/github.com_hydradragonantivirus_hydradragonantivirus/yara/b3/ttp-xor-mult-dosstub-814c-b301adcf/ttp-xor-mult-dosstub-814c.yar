rule TTP_XOR_MULT_DOSStub_814c {
  strings:
    $key_814c = { d5 24 [2] a1 3c [2] e6 3e [2] a1 2f [2] ef 23 [2] e3 29 [2] f4 22 [2] ef 6c [2] d2 }

  condition:
    any of them
}