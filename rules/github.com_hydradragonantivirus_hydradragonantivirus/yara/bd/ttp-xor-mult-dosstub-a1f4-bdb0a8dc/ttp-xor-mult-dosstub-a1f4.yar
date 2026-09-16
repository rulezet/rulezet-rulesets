rule TTP_XOR_MULT_DOSStub_a1f4 {
  strings:
    $key_a1f4 = { f5 9c [2] 81 84 [2] c6 86 [2] 81 97 [2] cf 9b [2] c3 91 [2] d4 9a [2] cf d4 [2] f2 }

  condition:
    any of them
}