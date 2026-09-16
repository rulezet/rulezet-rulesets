rule TTP_XOR_MULT_DOSStub_9c6d {
  strings:
    $key_9c6d = { c8 05 [2] bc 1d [2] fb 1f [2] bc 0e [2] f2 02 [2] fe 08 [2] e9 03 [2] f2 4d [2] cf }

  condition:
    any of them
}