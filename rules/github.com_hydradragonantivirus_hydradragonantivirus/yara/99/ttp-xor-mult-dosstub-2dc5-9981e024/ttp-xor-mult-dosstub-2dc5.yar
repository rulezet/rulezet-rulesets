rule TTP_XOR_MULT_DOSStub_2dc5 {
  strings:
    $key_2dc5 = { 79 ad [2] 0d b5 [2] 4a b7 [2] 0d a6 [2] 43 aa [2] 4f a0 [2] 58 ab [2] 43 e5 [2] 7e }

  condition:
    any of them
}