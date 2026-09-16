rule TTP_XOR_MULT_DOSStub_0bc5 {
  strings:
    $key_0bc5 = { 5f ad [2] 2b b5 [2] 6c b7 [2] 2b a6 [2] 65 aa [2] 69 a0 [2] 7e ab [2] 65 e5 [2] 58 }

  condition:
    any of them
}