rule TTP_XOR_MULT_DOSStub_9cdf {
  strings:
    $key_9cdf = { c8 b7 [2] bc af [2] fb ad [2] bc bc [2] f2 b0 [2] fe ba [2] e9 b1 [2] f2 ff [2] cf }

  condition:
    any of them
}