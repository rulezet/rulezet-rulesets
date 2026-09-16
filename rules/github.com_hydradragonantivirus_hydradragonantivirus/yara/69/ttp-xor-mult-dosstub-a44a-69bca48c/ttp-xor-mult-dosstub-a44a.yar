rule TTP_XOR_MULT_DOSStub_a44a {
  strings:
    $key_a44a = { f0 22 [2] 84 3a [2] c3 38 [2] 84 29 [2] ca 25 [2] c6 2f [2] d1 24 [2] ca 6a [2] f7 }

  condition:
    any of them
}