rule TTP_XOR_MULT_DOSStub_961c {
  strings:
    $key_961c = { c2 74 [2] b6 6c [2] f1 6e [2] b6 7f [2] f8 73 [2] f4 79 [2] e3 72 [2] f8 3c [2] c5 }

  condition:
    any of them
}