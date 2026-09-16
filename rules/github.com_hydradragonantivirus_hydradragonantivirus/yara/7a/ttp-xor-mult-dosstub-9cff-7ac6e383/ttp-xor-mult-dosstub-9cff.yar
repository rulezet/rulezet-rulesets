rule TTP_XOR_MULT_DOSStub_9cff {
  strings:
    $key_9cff = { c8 97 [2] bc 8f [2] fb 8d [2] bc 9c [2] f2 90 [2] fe 9a [2] e9 91 [2] f2 df [2] cf }

  condition:
    any of them
}