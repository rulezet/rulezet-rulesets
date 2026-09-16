rule TTP_XOR_MULT_DOSStub_9c89 {
  strings:
    $key_9c89 = { c8 e1 [2] bc f9 [2] fb fb [2] bc ea [2] f2 e6 [2] fe ec [2] e9 e7 [2] f2 a9 [2] cf }

  condition:
    any of them
}