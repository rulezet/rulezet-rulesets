rule TTP_XOR_MULT_DOSStub_7bd9 {
  strings:
    $key_7bd9 = { 2f b1 [2] 5b a9 [2] 1c ab [2] 5b ba [2] 15 b6 [2] 19 bc [2] 0e b7 [2] 15 f9 [2] 28 }

  condition:
    any of them
}