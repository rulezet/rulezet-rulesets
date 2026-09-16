rule TTP_XOR_MULT_DOSStub_a6c5 {
  strings:
    $key_a6c5 = { f2 ad [2] 86 b5 [2] c1 b7 [2] 86 a6 [2] c8 aa [2] c4 a0 [2] d3 ab [2] c8 e5 [2] f5 }

  condition:
    any of them
}