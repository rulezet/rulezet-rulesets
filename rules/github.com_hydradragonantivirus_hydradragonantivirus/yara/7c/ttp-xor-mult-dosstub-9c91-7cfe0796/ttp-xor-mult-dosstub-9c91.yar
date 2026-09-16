rule TTP_XOR_MULT_DOSStub_9c91 {
  strings:
    $key_9c91 = { c8 f9 [2] bc e1 [2] fb e3 [2] bc f2 [2] f2 fe [2] fe f4 [2] e9 ff [2] f2 b1 [2] cf }

  condition:
    any of them
}