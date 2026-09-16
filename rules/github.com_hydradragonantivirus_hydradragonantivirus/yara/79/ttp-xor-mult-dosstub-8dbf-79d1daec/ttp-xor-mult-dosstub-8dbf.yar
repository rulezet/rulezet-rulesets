rule TTP_XOR_MULT_DOSStub_8dbf {
  strings:
    $key_8dbf = { d9 d7 [2] ad cf [2] ea cd [2] ad dc [2] e3 d0 [2] ef da [2] f8 d1 [2] e3 9f [2] de }

  condition:
    any of them
}