rule TTP_XOR_MULT_DOSStub_8dc2 {
  strings:
    $key_8dc2 = { d9 aa [2] ad b2 [2] ea b0 [2] ad a1 [2] e3 ad [2] ef a7 [2] f8 ac [2] e3 e2 [2] de }

  condition:
    any of them
}