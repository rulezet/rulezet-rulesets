rule TTP_XOR_MULT_DOSStub_a074 {
  strings:
    $key_a074 = { f4 1c [2] 80 04 [2] c7 06 [2] 80 17 [2] ce 1b [2] c2 11 [2] d5 1a [2] ce 54 [2] f3 }

  condition:
    any of them
}