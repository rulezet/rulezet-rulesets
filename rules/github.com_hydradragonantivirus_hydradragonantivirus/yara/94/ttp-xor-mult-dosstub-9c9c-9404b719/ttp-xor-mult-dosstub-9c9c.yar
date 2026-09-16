rule TTP_XOR_MULT_DOSStub_9c9c {
  strings:
    $key_9c9c = { c8 f4 [2] bc ec [2] fb ee [2] bc ff [2] f2 f3 [2] fe f9 [2] e9 f2 [2] f2 bc [2] cf }

  condition:
    any of them
}