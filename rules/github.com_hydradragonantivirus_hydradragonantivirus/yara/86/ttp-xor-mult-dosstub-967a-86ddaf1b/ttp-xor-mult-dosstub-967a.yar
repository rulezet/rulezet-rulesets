rule TTP_XOR_MULT_DOSStub_967a {
  strings:
    $key_967a = { c2 12 [2] b6 0a [2] f1 08 [2] b6 19 [2] f8 15 [2] f4 1f [2] e3 14 [2] f8 5a [2] c5 }

  condition:
    any of them
}