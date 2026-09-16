rule TTP_XOR_MULT_DOSStub_a0e5 {
  strings:
    $key_a0e5 = { f4 8d [2] 80 95 [2] c7 97 [2] 80 86 [2] ce 8a [2] c2 80 [2] d5 8b [2] ce c5 [2] f3 }

  condition:
    any of them
}