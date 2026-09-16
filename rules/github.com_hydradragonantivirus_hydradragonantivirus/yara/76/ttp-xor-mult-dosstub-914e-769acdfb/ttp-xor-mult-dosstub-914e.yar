rule TTP_XOR_MULT_DOSStub_914e {
  strings:
    $key_914e = { c5 26 [2] b1 3e [2] f6 3c [2] b1 2d [2] ff 21 [2] f3 2b [2] e4 20 [2] ff 6e [2] c2 }

  condition:
    any of them
}