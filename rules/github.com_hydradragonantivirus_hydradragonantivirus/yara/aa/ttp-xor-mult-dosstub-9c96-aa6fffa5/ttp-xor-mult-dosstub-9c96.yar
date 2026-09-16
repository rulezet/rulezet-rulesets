rule TTP_XOR_MULT_DOSStub_9c96 {
  strings:
    $key_9c96 = { c8 fe [2] bc e6 [2] fb e4 [2] bc f5 [2] f2 f9 [2] fe f3 [2] e9 f8 [2] f2 b6 [2] cf }

  condition:
    any of them
}