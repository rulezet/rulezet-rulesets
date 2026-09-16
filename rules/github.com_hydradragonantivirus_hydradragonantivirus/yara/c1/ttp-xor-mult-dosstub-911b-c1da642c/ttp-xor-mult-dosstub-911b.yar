rule TTP_XOR_MULT_DOSStub_911b {
  strings:
    $key_911b = { c5 73 [2] b1 6b [2] f6 69 [2] b1 78 [2] ff 74 [2] f3 7e [2] e4 75 [2] ff 3b [2] c2 }

  condition:
    any of them
}