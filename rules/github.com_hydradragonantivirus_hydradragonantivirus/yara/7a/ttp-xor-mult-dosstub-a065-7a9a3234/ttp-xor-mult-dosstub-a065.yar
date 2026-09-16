rule TTP_XOR_MULT_DOSStub_a065 {
  strings:
    $key_a065 = { f4 0d [2] 80 15 [2] c7 17 [2] 80 06 [2] ce 0a [2] c2 00 [2] d5 0b [2] ce 45 [2] f3 }

  condition:
    any of them
}