rule TTP_XOR_MULT_DOSStub_d893 {
  strings:
    $key_d893 = { 8c fb [2] f8 e3 [2] bf e1 [2] f8 f0 [2] b6 fc [2] ba f6 [2] ad fd [2] b6 b3 [2] 8b }

  condition:
    any of them
}