rule TTP_XOR_MULT_DOSStub_a45a {
  strings:
    $key_a45a = { f0 32 [2] 84 2a [2] c3 28 [2] 84 39 [2] ca 35 [2] c6 3f [2] d1 34 [2] ca 7a [2] f7 }

  condition:
    any of them
}