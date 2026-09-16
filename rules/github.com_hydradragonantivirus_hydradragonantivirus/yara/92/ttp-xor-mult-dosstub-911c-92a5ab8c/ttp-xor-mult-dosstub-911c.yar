rule TTP_XOR_MULT_DOSStub_911c {
  strings:
    $key_911c = { c5 74 [2] b1 6c [2] f6 6e [2] b1 7f [2] ff 73 [2] f3 79 [2] e4 72 [2] ff 3c [2] c2 }

  condition:
    any of them
}