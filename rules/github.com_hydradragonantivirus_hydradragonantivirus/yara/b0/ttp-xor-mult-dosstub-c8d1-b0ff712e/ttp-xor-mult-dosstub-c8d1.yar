rule TTP_XOR_MULT_DOSStub_c8d1 {
  strings:
    $key_c8d1 = { 9c b9 [2] e8 a1 [2] af a3 [2] e8 b2 [2] a6 be [2] aa b4 [2] bd bf [2] a6 f1 [2] 9b }

  condition:
    any of them
}