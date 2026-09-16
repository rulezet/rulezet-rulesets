rule TTP_XOR_MULT_DOSStub_9edb {
  strings:
    $key_9edb = { ca b3 [2] be ab [2] f9 a9 [2] be b8 [2] f0 b4 [2] fc be [2] eb b5 [2] f0 fb [2] cd }

  condition:
    any of them
}