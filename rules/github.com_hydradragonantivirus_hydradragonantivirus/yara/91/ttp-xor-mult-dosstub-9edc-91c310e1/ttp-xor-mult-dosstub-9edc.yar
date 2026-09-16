rule TTP_XOR_MULT_DOSStub_9edc {
  strings:
    $key_9edc = { ca b4 [2] be ac [2] f9 ae [2] be bf [2] f0 b3 [2] fc b9 [2] eb b2 [2] f0 fc [2] cd }

  condition:
    any of them
}