rule TTP_XOR_MULT_DOSStub_914c {
  strings:
    $key_914c = { c5 24 [2] b1 3c [2] f6 3e [2] b1 2f [2] ff 23 [2] f3 29 [2] e4 22 [2] ff 6c [2] c2 }

  condition:
    any of them
}