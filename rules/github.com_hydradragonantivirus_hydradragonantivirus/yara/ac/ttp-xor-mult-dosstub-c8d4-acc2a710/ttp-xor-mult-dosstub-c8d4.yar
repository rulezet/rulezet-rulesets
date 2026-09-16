rule TTP_XOR_MULT_DOSStub_c8d4 {
  strings:
    $key_c8d4 = { 9c bc [2] e8 a4 [2] af a6 [2] e8 b7 [2] a6 bb [2] aa b1 [2] bd ba [2] a6 f4 [2] 9b }

  condition:
    any of them
}