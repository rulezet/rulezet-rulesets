rule TTP_XOR_MULT_DOSStub_9ede {
  strings:
    $key_9ede = { ca b6 [2] be ae [2] f9 ac [2] be bd [2] f0 b1 [2] fc bb [2] eb b0 [2] f0 fe [2] cd }

  condition:
    any of them
}