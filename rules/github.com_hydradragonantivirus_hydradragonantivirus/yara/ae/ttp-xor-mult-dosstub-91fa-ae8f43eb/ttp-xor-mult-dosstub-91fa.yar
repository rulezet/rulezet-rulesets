rule TTP_XOR_MULT_DOSStub_91fa {
  strings:
    $key_91fa = { c5 92 [2] b1 8a [2] f6 88 [2] b1 99 [2] ff 95 [2] f3 9f [2] e4 94 [2] ff da [2] c2 }

  condition:
    any of them
}