rule TTP_XOR_MULT_DOSStub_8dac {
  strings:
    $key_8dac = { d9 c4 [2] ad dc [2] ea de [2] ad cf [2] e3 c3 [2] ef c9 [2] f8 c2 [2] e3 8c [2] de }

  condition:
    any of them
}