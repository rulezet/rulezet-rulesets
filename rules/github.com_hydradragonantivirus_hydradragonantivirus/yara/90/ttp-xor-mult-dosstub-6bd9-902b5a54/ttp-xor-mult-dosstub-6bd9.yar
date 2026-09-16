rule TTP_XOR_MULT_DOSStub_6bd9 {
  strings:
    $key_6bd9 = { 3f b1 [2] 4b a9 [2] 0c ab [2] 4b ba [2] 05 b6 [2] 09 bc [2] 1e b7 [2] 05 f9 [2] 38 }

  condition:
    any of them
}