rule TTP_XOR_MULT_DOSStub_9c6c {
  strings:
    $key_9c6c = { c8 04 [2] bc 1c [2] fb 1e [2] bc 0f [2] f2 03 [2] fe 09 [2] e9 02 [2] f2 4c [2] cf }

  condition:
    any of them
}