rule TTP_XOR_MULT_DOSStub_1cd3 {
  strings:
    $key_1cd3 = { 48 bb [2] 3c a3 [2] 7b a1 [2] 3c b0 [2] 72 bc [2] 7e b6 [2] 69 bd [2] 72 f3 [2] 4f }

  condition:
    any of them
}