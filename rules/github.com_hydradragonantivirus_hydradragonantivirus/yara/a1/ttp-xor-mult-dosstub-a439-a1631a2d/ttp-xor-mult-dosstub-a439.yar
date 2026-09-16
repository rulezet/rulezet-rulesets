rule TTP_XOR_MULT_DOSStub_a439 {
  strings:
    $key_a439 = { f0 51 [2] 84 49 [2] c3 4b [2] 84 5a [2] ca 56 [2] c6 5c [2] d1 57 [2] ca 19 [2] f7 }

  condition:
    any of them
}