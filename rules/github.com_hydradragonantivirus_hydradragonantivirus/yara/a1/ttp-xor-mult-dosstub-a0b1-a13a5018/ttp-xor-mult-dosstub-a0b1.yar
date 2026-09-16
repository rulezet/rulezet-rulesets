rule TTP_XOR_MULT_DOSStub_a0b1 {
  strings:
    $key_a0b1 = { f4 d9 [2] 80 c1 [2] c7 c3 [2] 80 d2 [2] ce de [2] c2 d4 [2] d5 df [2] ce 91 [2] f3 }

  condition:
    any of them
}