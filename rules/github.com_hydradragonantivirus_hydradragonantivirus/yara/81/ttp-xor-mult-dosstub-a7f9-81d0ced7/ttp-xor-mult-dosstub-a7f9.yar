rule TTP_XOR_MULT_DOSStub_a7f9 {
  strings:
    $key_a7f9 = { f3 91 [2] 87 89 [2] c0 8b [2] 87 9a [2] c9 96 [2] c5 9c [2] d2 97 [2] c9 d9 [2] f4 }

  condition:
    any of them
}