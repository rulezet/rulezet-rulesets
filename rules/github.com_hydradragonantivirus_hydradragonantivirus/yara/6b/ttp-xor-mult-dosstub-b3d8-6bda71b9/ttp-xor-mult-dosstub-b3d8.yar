rule TTP_XOR_MULT_DOSStub_b3d8 {
  strings:
    $key_b3d8 = { e7 b0 [2] 93 a8 [2] d4 aa [2] 93 bb [2] dd b7 [2] d1 bd [2] c6 b6 [2] dd f8 [2] e0 }

  condition:
    any of them
}