rule TTP_XOR_MULT_DOSStub_91f6 {
  strings:
    $key_91f6 = { c5 9e [2] b1 86 [2] f6 84 [2] b1 95 [2] ff 99 [2] f3 93 [2] e4 98 [2] ff d6 [2] c2 }

  condition:
    any of them
}