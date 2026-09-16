rule TTP_XOR_MULT_DOSStub_5bd9 {
  strings:
    $key_5bd9 = { 0f b1 [2] 7b a9 [2] 3c ab [2] 7b ba [2] 35 b6 [2] 39 bc [2] 2e b7 [2] 35 f9 [2] 08 }

  condition:
    any of them
}