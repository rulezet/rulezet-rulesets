rule TTP_XOR_MULT_DOSStub_a0b3 {
  strings:
    $key_a0b3 = { f4 db [2] 80 c3 [2] c7 c1 [2] 80 d0 [2] ce dc [2] c2 d6 [2] d5 dd [2] ce 93 [2] f3 }

  condition:
    any of them
}