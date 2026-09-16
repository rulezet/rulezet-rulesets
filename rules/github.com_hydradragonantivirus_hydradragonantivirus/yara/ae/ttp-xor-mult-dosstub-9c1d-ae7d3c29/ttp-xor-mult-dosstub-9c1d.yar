rule TTP_XOR_MULT_DOSStub_9c1d {
  strings:
    $key_9c1d = { c8 75 [2] bc 6d [2] fb 6f [2] bc 7e [2] f2 72 [2] fe 78 [2] e9 73 [2] f2 3d [2] cf }

  condition:
    any of them
}