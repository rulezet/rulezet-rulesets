rule TTP_XOR_MULT_DOSStub_2cc2 {
  strings:
    $key_2cc2 = { 78 aa [2] 0c b2 [2] 4b b0 [2] 0c a1 [2] 42 ad [2] 4e a7 [2] 59 ac [2] 42 e2 [2] 7f }

  condition:
    any of them
}