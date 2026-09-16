rule TTP_XOR_MULT_DOSStub_91e4 {
  strings:
    $key_91e4 = { c5 8c [2] b1 94 [2] f6 96 [2] b1 87 [2] ff 8b [2] f3 81 [2] e4 8a [2] ff c4 [2] c2 }

  condition:
    any of them
}