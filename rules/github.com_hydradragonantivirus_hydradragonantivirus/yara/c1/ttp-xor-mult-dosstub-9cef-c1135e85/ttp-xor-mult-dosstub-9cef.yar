rule TTP_XOR_MULT_DOSStub_9cef {
  strings:
    $key_9cef = { c8 87 [2] bc 9f [2] fb 9d [2] bc 8c [2] f2 80 [2] fe 8a [2] e9 81 [2] f2 cf [2] cf }

  condition:
    any of them
}