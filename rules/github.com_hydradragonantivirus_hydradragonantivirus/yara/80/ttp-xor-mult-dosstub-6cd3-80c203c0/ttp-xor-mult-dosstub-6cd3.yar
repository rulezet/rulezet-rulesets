rule TTP_XOR_MULT_DOSStub_6cd3 {
  strings:
    $key_6cd3 = { 38 bb [2] 4c a3 [2] 0b a1 [2] 4c b0 [2] 02 bc [2] 0e b6 [2] 19 bd [2] 02 f3 [2] 3f }

  condition:
    any of them
}