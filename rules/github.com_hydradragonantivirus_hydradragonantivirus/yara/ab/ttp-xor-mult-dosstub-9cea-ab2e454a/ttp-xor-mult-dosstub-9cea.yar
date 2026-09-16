rule TTP_XOR_MULT_DOSStub_9cea {
  strings:
    $key_9cea = { c8 82 [2] bc 9a [2] fb 98 [2] bc 89 [2] f2 85 [2] fe 8f [2] e9 84 [2] f2 ca [2] cf }

  condition:
    any of them
}