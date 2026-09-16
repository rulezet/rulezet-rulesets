rule TTP_XOR_MULT_DOSStub_9c8f {
  strings:
    $key_9c8f = { c8 e7 [2] bc ff [2] fb fd [2] bc ec [2] f2 e0 [2] fe ea [2] e9 e1 [2] f2 af [2] cf }

  condition:
    any of them
}