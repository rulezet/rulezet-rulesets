rule TTP_XOR_MULT_DOSStub_962a {
  strings:
    $key_962a = { c2 42 [2] b6 5a [2] f1 58 [2] b6 49 [2] f8 45 [2] f4 4f [2] e3 44 [2] f8 0a [2] c5 }

  condition:
    any of them
}