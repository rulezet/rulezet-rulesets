rule TTP_XOR_MULT_DOSStub_7dc5 {
  strings:
    $key_7dc5 = { 29 ad [2] 5d b5 [2] 1a b7 [2] 5d a6 [2] 13 aa [2] 1f a0 [2] 08 ab [2] 13 e5 [2] 2e }

  condition:
    any of them
}