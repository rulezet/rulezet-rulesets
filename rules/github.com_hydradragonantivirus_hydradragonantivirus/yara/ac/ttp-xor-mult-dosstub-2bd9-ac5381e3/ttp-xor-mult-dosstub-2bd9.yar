rule TTP_XOR_MULT_DOSStub_2bd9 {
  strings:
    $key_2bd9 = { 7f b1 [2] 0b a9 [2] 4c ab [2] 0b ba [2] 45 b6 [2] 49 bc [2] 5e b7 [2] 45 f9 [2] 78 }

  condition:
    any of them
}