rule TTP_XOR_MULT_DOSStub_9ecd {
  strings:
    $key_9ecd = { ca a5 [2] be bd [2] f9 bf [2] be ae [2] f0 a2 [2] fc a8 [2] eb a3 [2] f0 ed [2] cd }

  condition:
    any of them
}