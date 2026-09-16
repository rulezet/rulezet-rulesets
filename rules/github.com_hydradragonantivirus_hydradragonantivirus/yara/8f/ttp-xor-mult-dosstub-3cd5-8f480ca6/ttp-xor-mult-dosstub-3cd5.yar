rule TTP_XOR_MULT_DOSStub_3cd5 {
  strings:
    $key_3cd5 = { 68 bd [2] 1c a5 [2] 5b a7 [2] 1c b6 [2] 52 ba [2] 5e b0 [2] 49 bb [2] 52 f5 [2] 6f }

  condition:
    any of them
}