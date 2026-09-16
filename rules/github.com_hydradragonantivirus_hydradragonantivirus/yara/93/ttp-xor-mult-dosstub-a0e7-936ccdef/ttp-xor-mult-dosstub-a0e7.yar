rule TTP_XOR_MULT_DOSStub_a0e7 {
  strings:
    $key_a0e7 = { f4 8f [2] 80 97 [2] c7 95 [2] 80 84 [2] ce 88 [2] c2 82 [2] d5 89 [2] ce c7 [2] f3 }

  condition:
    any of them
}