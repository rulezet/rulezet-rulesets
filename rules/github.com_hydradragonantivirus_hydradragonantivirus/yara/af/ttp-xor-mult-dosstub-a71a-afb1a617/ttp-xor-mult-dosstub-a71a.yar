rule TTP_XOR_MULT_DOSStub_a71a {
  strings:
    $key_a71a = { f3 72 [2] 87 6a [2] c0 68 [2] 87 79 [2] c9 75 [2] c5 7f [2] d2 74 [2] c9 3a [2] f4 }

  condition:
    any of them
}