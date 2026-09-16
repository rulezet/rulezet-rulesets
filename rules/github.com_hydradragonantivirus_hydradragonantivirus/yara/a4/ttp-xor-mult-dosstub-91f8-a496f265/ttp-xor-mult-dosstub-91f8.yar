rule TTP_XOR_MULT_DOSStub_91f8 {
  strings:
    $key_91f8 = { c5 90 [2] b1 88 [2] f6 8a [2] b1 9b [2] ff 97 [2] f3 9d [2] e4 96 [2] ff d8 [2] c2 }

  condition:
    any of them
}