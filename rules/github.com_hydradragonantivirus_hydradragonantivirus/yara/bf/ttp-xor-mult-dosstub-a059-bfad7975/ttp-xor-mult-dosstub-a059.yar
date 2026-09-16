rule TTP_XOR_MULT_DOSStub_a059 {
  strings:
    $key_a059 = { f4 31 [2] 80 29 [2] c7 2b [2] 80 3a [2] ce 36 [2] c2 3c [2] d5 37 [2] ce 79 [2] f3 }

  condition:
    any of them
}