rule TTP_XOR_MULT_DOSStub_d9d4 {
  strings:
    $key_d9d4 = { 8d bc [2] f9 a4 [2] be a6 [2] f9 b7 [2] b7 bb [2] bb b1 [2] ac ba [2] b7 f4 [2] 8a }

  condition:
    any of them
}