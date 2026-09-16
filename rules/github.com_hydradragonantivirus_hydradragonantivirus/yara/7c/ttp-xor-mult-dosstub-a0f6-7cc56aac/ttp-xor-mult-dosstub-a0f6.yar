rule TTP_XOR_MULT_DOSStub_a0f6 {
  strings:
    $key_a0f6 = { f4 9e [2] 80 86 [2] c7 84 [2] 80 95 [2] ce 99 [2] c2 93 [2] d5 98 [2] ce d6 [2] f3 }

  condition:
    any of them
}