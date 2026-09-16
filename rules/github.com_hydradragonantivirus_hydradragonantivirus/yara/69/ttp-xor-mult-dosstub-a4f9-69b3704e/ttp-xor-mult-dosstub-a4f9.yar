rule TTP_XOR_MULT_DOSStub_a4f9 {
  strings:
    $key_a4f9 = { f0 91 [2] 84 89 [2] c3 8b [2] 84 9a [2] ca 96 [2] c6 9c [2] d1 97 [2] ca d9 [2] f7 }

  condition:
    any of them
}