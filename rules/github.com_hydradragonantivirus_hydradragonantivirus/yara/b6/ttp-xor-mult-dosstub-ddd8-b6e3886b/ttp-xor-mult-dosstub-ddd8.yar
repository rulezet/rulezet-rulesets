rule TTP_XOR_MULT_DOSStub_ddd8 {
  strings:
    $key_ddd8 = { 89 b0 [2] fd a8 [2] ba aa [2] fd bb [2] b3 b7 [2] bf bd [2] a8 b6 [2] b3 f8 [2] 8e }

  condition:
    any of them
}