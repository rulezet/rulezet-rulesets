rule TTP_XOR_MULT_DOSStub_9ecb {
  strings:
    $key_9ecb = { ca a3 [2] be bb [2] f9 b9 [2] be a8 [2] f0 a4 [2] fc ae [2] eb a5 [2] f0 eb [2] cd }

  condition:
    any of them
}