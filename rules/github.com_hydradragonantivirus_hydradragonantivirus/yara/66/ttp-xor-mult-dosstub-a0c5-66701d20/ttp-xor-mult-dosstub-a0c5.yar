rule TTP_XOR_MULT_DOSStub_a0c5 {
  strings:
    $key_a0c5 = { f4 ad [2] 80 b5 [2] c7 b7 [2] 80 a6 [2] ce aa [2] c2 a0 [2] d5 ab [2] ce e5 [2] f3 }

  condition:
    any of them
}