rule TTP_XOR_MULT_DOSStub_6cd5 {
  strings:
    $key_6cd5 = { 38 bd [2] 4c a5 [2] 0b a7 [2] 4c b6 [2] 02 ba [2] 0e b0 [2] 19 bb [2] 02 f5 [2] 3f }

  condition:
    any of them
}