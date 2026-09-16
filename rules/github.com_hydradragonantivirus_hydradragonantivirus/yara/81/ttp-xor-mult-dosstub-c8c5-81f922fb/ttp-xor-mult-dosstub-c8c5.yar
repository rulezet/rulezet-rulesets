rule TTP_XOR_MULT_DOSStub_c8c5 {
  strings:
    $key_c8c5 = { 9c ad [2] e8 b5 [2] af b7 [2] e8 a6 [2] a6 aa [2] aa a0 [2] bd ab [2] a6 e5 [2] 9b }

  condition:
    any of them
}