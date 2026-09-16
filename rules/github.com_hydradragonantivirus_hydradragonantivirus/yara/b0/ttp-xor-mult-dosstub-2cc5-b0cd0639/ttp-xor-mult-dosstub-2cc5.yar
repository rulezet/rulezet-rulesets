rule TTP_XOR_MULT_DOSStub_2cc5 {
  strings:
    $key_2cc5 = { 78 ad [2] 0c b5 [2] 4b b7 [2] 0c a6 [2] 42 aa [2] 4e a0 [2] 59 ab [2] 42 e5 [2] 7f }

  condition:
    any of them
}