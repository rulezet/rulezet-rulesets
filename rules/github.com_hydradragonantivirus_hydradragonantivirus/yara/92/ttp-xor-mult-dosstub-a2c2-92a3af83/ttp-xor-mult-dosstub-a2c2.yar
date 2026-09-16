rule TTP_XOR_MULT_DOSStub_a2c2 {
  strings:
    $key_a2c2 = { f6 aa [2] 82 b2 [2] c5 b0 [2] 82 a1 [2] cc ad [2] c0 a7 [2] d7 ac [2] cc e2 [2] f1 }

  condition:
    any of them
}