rule TTP_XOR_MULT_DOSStub_9c90 {
  strings:
    $key_9c90 = { c8 f8 [2] bc e0 [2] fb e2 [2] bc f3 [2] f2 ff [2] fe f5 [2] e9 fe [2] f2 b0 [2] cf }

  condition:
    any of them
}