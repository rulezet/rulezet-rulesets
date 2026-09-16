rule TTP_XOR_MULT_DOSStub_6dc4 {
  strings:
    $key_6dc4 = { 39 ac [2] 4d b4 [2] 0a b6 [2] 4d a7 [2] 03 ab [2] 0f a1 [2] 18 aa [2] 03 e4 [2] 3e }

  condition:
    any of them
}