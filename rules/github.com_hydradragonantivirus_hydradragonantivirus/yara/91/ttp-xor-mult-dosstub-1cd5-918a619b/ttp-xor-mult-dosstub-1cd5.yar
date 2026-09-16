rule TTP_XOR_MULT_DOSStub_1cd5 {
  strings:
    $key_1cd5 = { 48 bd [2] 3c a5 [2] 7b a7 [2] 3c b6 [2] 72 ba [2] 7e b0 [2] 69 bb [2] 72 f5 [2] 4f }

  condition:
    any of them
}