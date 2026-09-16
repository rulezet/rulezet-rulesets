rule TTP_XOR_MULT_DOSStub_91fc {
  strings:
    $key_91fc = { c5 94 [2] b1 8c [2] f6 8e [2] b1 9f [2] ff 93 [2] f3 99 [2] e4 92 [2] ff dc [2] c2 }

  condition:
    any of them
}