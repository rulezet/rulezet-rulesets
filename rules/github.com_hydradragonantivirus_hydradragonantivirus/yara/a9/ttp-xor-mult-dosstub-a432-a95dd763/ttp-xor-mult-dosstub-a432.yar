rule TTP_XOR_MULT_DOSStub_a432 {
  strings:
    $key_a432 = { f0 5a [2] 84 42 [2] c3 40 [2] 84 51 [2] ca 5d [2] c6 57 [2] d1 5c [2] ca 12 [2] f7 }

  condition:
    any of them
}