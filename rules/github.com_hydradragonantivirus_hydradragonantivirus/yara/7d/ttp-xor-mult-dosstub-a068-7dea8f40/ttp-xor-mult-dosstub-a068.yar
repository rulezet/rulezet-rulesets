rule TTP_XOR_MULT_DOSStub_a068 {
  strings:
    $key_a068 = { f4 00 [2] 80 18 [2] c7 1a [2] 80 0b [2] ce 07 [2] c2 0d [2] d5 06 [2] ce 48 [2] f3 }

  condition:
    any of them
}