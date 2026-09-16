rule TTP_XOR_MULT_DOSStub_5dc5 {
  strings:
    $key_5dc5 = { 09 ad [2] 7d b5 [2] 3a b7 [2] 7d a6 [2] 33 aa [2] 3f a0 [2] 28 ab [2] 33 e5 [2] 0e }

  condition:
    any of them
}