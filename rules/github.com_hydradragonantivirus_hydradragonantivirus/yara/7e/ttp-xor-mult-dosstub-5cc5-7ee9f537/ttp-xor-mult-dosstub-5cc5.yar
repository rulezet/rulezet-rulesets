rule TTP_XOR_MULT_DOSStub_5cc5 {
  strings:
    $key_5cc5 = { 08 ad [2] 7c b5 [2] 3b b7 [2] 7c a6 [2] 32 aa [2] 3e a0 [2] 29 ab [2] 32 e5 [2] 0f }

  condition:
    any of them
}