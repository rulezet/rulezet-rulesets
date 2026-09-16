rule TTP_XOR_MULT_DOSStub_91a6 {
  strings:
    $key_91a6 = { c5 ce [2] b1 d6 [2] f6 d4 [2] b1 c5 [2] ff c9 [2] f3 c3 [2] e4 c8 [2] ff 86 [2] c2 }

  condition:
    any of them
}