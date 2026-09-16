rule TTP_XOR_MULT_DOSStub_a0fa {
  strings:
    $key_a0fa = { f4 92 [2] 80 8a [2] c7 88 [2] 80 99 [2] ce 95 [2] c2 9f [2] d5 94 [2] ce da [2] f3 }

  condition:
    any of them
}