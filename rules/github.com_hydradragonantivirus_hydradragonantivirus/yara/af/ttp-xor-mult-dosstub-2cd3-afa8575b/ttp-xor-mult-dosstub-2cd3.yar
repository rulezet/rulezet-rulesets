rule TTP_XOR_MULT_DOSStub_2cd3 {
  strings:
    $key_2cd3 = { 78 bb [2] 0c a3 [2] 4b a1 [2] 0c b0 [2] 42 bc [2] 4e b6 [2] 59 bd [2] 42 f3 [2] 7f }

  condition:
    any of them
}