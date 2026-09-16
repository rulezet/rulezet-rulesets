rule TTP_XOR_MULT_DOSStub_e6d8 {
  strings:
    $key_e6d8 = { b2 b0 [2] c6 a8 [2] 81 aa [2] c6 bb [2] 88 b7 [2] 84 bd [2] 93 b6 [2] 88 f8 [2] b5 }

  condition:
    any of them
}