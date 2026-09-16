rule TTP_XOR_MULT_DOSStub_a6f9 {
  strings:
    $key_a6f9 = { f2 91 [2] 86 89 [2] c1 8b [2] 86 9a [2] c8 96 [2] c4 9c [2] d3 97 [2] c8 d9 [2] f5 }

  condition:
    any of them
}