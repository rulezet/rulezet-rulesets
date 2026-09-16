rule TTP_XOR_MULT_DOSStub_d4d5 {
  strings:
    $key_d4d5 = { 80 bd [2] f4 a5 [2] b3 a7 [2] f4 b6 [2] ba ba [2] b6 b0 [2] a1 bb [2] ba f5 [2] 87 }

  condition:
    any of them
}