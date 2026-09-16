rule TTP_XOR_MULT_DOSStub_9cf3 {
  strings:
    $key_9cf3 = { c8 9b [2] bc 83 [2] fb 81 [2] bc 90 [2] f2 9c [2] fe 96 [2] e9 9d [2] f2 d3 [2] cf }

  condition:
    any of them
}