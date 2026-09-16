rule TTP_XOR_MULT_DOSStub_9ec9 {
  strings:
    $key_9ec9 = { ca a1 [2] be b9 [2] f9 bb [2] be aa [2] f0 a6 [2] fc ac [2] eb a7 [2] f0 e9 [2] cd }

  condition:
    any of them
}