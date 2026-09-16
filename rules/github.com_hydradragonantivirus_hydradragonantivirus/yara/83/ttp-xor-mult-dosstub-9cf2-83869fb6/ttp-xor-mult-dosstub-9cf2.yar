rule TTP_XOR_MULT_DOSStub_9cf2 {
  strings:
    $key_9cf2 = { c8 9a [2] bc 82 [2] fb 80 [2] bc 91 [2] f2 9d [2] fe 97 [2] e9 9c [2] f2 d2 [2] cf }

  condition:
    any of them
}