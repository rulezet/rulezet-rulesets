rule TTP_XOR_MULT_DOSStub_9cca {
  strings:
    $key_9cca = { c8 a2 [2] bc ba [2] fb b8 [2] bc a9 [2] f2 a5 [2] fe af [2] e9 a4 [2] f2 ea [2] cf }

  condition:
    any of them
}