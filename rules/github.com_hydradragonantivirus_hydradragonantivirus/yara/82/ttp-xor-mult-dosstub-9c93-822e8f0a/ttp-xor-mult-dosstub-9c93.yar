rule TTP_XOR_MULT_DOSStub_9c93 {
  strings:
    $key_9c93 = { c8 fb [2] bc e3 [2] fb e1 [2] bc f0 [2] f2 fc [2] fe f6 [2] e9 fd [2] f2 b3 [2] cf }

  condition:
    any of them
}