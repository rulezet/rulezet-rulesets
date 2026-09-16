rule TTP_XOR_MULT_DOSStub_7cc5 {
  strings:
    $key_7cc5 = { 28 ad [2] 5c b5 [2] 1b b7 [2] 5c a6 [2] 12 aa [2] 1e a0 [2] 09 ab [2] 12 e5 [2] 2f }

  condition:
    any of them
}