rule TTP_XOR_MULT_DOSStub_9c2f {
  strings:
    $key_9c2f = { c8 47 [2] bc 5f [2] fb 5d [2] bc 4c [2] f2 40 [2] fe 4a [2] e9 41 [2] f2 0f [2] cf }

  condition:
    any of them
}