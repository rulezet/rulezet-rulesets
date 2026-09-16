rule TTP_XOR_MULT_DOSStub_9c8e {
  strings:
    $key_9c8e = { c8 e6 [2] bc fe [2] fb fc [2] bc ed [2] f2 e1 [2] fe eb [2] e9 e0 [2] f2 ae [2] cf }

  condition:
    any of them
}