rule TTP_XOR_MULT_DOSStub_a4f8 {
  strings:
    $key_a4f8 = { f0 90 [2] 84 88 [2] c3 8a [2] 84 9b [2] ca 97 [2] c6 9d [2] d1 96 [2] ca d8 [2] f7 }

  condition:
    any of them
}