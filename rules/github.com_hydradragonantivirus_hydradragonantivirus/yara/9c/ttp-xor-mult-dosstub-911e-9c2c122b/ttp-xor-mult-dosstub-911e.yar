rule TTP_XOR_MULT_DOSStub_911e {
  strings:
    $key_911e = { c5 76 [2] b1 6e [2] f6 6c [2] b1 7d [2] ff 71 [2] f3 7b [2] e4 70 [2] ff 3e [2] c2 }

  condition:
    any of them
}