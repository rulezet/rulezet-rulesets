rule TTP_XOR_MULT_DOSStub_6dc2 {
  strings:
    $key_6dc2 = { 39 aa [2] 4d b2 [2] 0a b0 [2] 4d a1 [2] 03 ad [2] 0f a7 [2] 18 ac [2] 03 e2 [2] 3e }

  condition:
    any of them
}