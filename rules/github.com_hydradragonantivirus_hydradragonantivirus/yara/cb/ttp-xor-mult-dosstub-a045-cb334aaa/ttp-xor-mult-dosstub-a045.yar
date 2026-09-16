rule TTP_XOR_MULT_DOSStub_a045 {
  strings:
    $key_a045 = { f4 2d [2] 80 35 [2] c7 37 [2] 80 26 [2] ce 2a [2] c2 20 [2] d5 2b [2] ce 65 [2] f3 }

  condition:
    any of them
}