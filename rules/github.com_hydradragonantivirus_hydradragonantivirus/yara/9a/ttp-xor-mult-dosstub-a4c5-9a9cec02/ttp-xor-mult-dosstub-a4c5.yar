rule TTP_XOR_MULT_DOSStub_a4c5 {
  strings:
    $key_a4c5 = { f0 ad [2] 84 b5 [2] c3 b7 [2] 84 a6 [2] ca aa [2] c6 a0 [2] d1 ab [2] ca e5 [2] f7 }

  condition:
    any of them
}