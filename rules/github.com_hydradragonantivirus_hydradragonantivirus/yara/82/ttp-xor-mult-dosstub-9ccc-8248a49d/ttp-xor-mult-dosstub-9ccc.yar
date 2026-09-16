rule TTP_XOR_MULT_DOSStub_9ccc {
  strings:
    $key_9ccc = { c8 a4 [2] bc bc [2] fb be [2] bc af [2] f2 a3 [2] fe a9 [2] e9 a2 [2] f2 ec [2] cf }

  condition:
    any of them
}