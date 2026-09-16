rule TTP_XOR_MULT_DOSStub_a018 {
  strings:
    $key_a018 = { f4 70 [2] 80 68 [2] c7 6a [2] 80 7b [2] ce 77 [2] c2 7d [2] d5 76 [2] ce 38 [2] f3 }

  condition:
    any of them
}