rule TTP_XOR_MULT_DOSStub_8d8d {
  strings:
    $key_8d8d = { d9 e5 [2] ad fd [2] ea ff [2] ad ee [2] e3 e2 [2] ef e8 [2] f8 e3 [2] e3 ad [2] de }

  condition:
    any of them
}