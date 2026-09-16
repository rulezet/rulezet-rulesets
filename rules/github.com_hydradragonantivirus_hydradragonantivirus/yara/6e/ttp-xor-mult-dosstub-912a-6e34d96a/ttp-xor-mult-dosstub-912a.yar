rule TTP_XOR_MULT_DOSStub_912a {
  strings:
    $key_912a = { c5 42 [2] b1 5a [2] f6 58 [2] b1 49 [2] ff 45 [2] f3 4f [2] e4 44 [2] ff 0a [2] c2 }

  condition:
    any of them
}