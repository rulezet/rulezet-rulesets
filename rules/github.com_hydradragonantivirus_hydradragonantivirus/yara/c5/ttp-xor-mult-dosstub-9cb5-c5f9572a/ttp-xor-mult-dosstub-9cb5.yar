rule TTP_XOR_MULT_DOSStub_9cb5 {
  strings:
    $key_9cb5 = { c8 dd [2] bc c5 [2] fb c7 [2] bc d6 [2] f2 da [2] fe d0 [2] e9 db [2] f2 95 [2] cf }

  condition:
    any of them
}