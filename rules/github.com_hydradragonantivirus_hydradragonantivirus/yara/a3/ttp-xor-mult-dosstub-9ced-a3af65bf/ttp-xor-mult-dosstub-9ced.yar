rule TTP_XOR_MULT_DOSStub_9ced {
  strings:
    $key_9ced = { c8 85 [2] bc 9d [2] fb 9f [2] bc 8e [2] f2 82 [2] fe 88 [2] e9 83 [2] f2 cd [2] cf }

  condition:
    any of them
}