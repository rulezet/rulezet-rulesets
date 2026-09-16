rule TTP_XOR_MULT_DOSStub_a464 {
  strings:
    $key_a464 = { f0 0c [2] 84 14 [2] c3 16 [2] 84 07 [2] ca 0b [2] c6 01 [2] d1 0a [2] ca 44 [2] f7 }

  condition:
    any of them
}