rule TTP_XOR_MULT_DOSStub_3cc5 {
  strings:
    $key_3cc5 = { 68 ad [2] 1c b5 [2] 5b b7 [2] 1c a6 [2] 52 aa [2] 5e a0 [2] 49 ab [2] 52 e5 [2] 6f }

  condition:
    any of them
}