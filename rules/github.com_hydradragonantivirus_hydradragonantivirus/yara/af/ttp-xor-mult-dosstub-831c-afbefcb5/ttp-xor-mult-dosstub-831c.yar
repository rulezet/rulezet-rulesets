rule TTP_XOR_MULT_DOSStub_831c {
  strings:
    $key_831c = { d7 74 [2] a3 6c [2] e4 6e [2] a3 7f [2] ed 73 [2] e1 79 [2] f6 72 [2] ed 3c [2] d0 }

  condition:
    any of them
}