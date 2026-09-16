rule TTP_XOR_MULT_DOSStub_a41a {
  strings:
    $key_a41a = { f0 72 [2] 84 6a [2] c3 68 [2] 84 79 [2] ca 75 [2] c6 7f [2] d1 74 [2] ca 3a [2] f7 }

  condition:
    any of them
}