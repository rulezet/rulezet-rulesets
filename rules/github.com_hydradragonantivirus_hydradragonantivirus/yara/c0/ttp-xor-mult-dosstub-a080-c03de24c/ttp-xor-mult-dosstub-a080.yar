rule TTP_XOR_MULT_DOSStub_a080 {
  strings:
    $key_a080 = { f4 e8 [2] 80 f0 [2] c7 f2 [2] 80 e3 [2] ce ef [2] c2 e5 [2] d5 ee [2] ce a0 [2] f3 }

  condition:
    any of them
}