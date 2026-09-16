rule TTP_XOR_MULT_DOSStub_e2d8 {
  strings:
    $key_e2d8 = { b6 b0 [2] c2 a8 [2] 85 aa [2] c2 bb [2] 8c b7 [2] 80 bd [2] 97 b6 [2] 8c f8 [2] b1 }

  condition:
    any of them
}