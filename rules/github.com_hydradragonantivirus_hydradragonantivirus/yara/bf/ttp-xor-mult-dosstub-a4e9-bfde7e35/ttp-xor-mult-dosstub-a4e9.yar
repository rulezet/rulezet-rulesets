rule TTP_XOR_MULT_DOSStub_a4e9 {
  strings:
    $key_a4e9 = { f0 81 [2] 84 99 [2] c3 9b [2] 84 8a [2] ca 86 [2] c6 8c [2] d1 87 [2] ca c9 [2] f7 }

  condition:
    any of them
}