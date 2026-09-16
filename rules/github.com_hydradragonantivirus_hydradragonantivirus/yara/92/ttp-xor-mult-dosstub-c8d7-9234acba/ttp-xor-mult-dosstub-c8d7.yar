rule TTP_XOR_MULT_DOSStub_c8d7 {
  strings:
    $key_c8d7 = { 9c bf [2] e8 a7 [2] af a5 [2] e8 b4 [2] a6 b8 [2] aa b2 [2] bd b9 [2] a6 f7 [2] 9b }

  condition:
    any of them
}