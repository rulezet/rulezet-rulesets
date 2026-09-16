rule TTP_XOR_MULT_DOSStub_917a {
  strings:
    $key_917a = { c5 12 [2] b1 0a [2] f6 08 [2] b1 19 [2] ff 15 [2] f3 1f [2] e4 14 [2] ff 5a [2] c2 }

  condition:
    any of them
}