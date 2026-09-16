rule TTP_XOR_MULT_DOSStub_a4e4 {
  strings:
    $key_a4e4 = { f0 8c [2] 84 94 [2] c3 96 [2] 84 87 [2] ca 8b [2] c6 81 [2] d1 8a [2] ca c4 [2] f7 }

  condition:
    any of them
}