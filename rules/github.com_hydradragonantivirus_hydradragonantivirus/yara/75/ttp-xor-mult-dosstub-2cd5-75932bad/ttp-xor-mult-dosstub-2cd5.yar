rule TTP_XOR_MULT_DOSStub_2cd5 {
  strings:
    $key_2cd5 = { 78 bd [2] 0c a5 [2] 4b a7 [2] 0c b6 [2] 42 ba [2] 4e b0 [2] 59 bb [2] 42 f5 [2] 7f }

  condition:
    any of them
}