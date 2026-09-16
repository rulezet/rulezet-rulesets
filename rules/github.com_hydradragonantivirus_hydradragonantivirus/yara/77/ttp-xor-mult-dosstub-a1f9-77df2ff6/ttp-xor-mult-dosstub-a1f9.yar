rule TTP_XOR_MULT_DOSStub_a1f9 {
  strings:
    $key_a1f9 = { f5 91 [2] 81 89 [2] c6 8b [2] 81 9a [2] cf 96 [2] c3 9c [2] d4 97 [2] cf d9 [2] f2 }

  condition:
    any of them
}