rule TTP_XOR_MULT_DOSStub_9ed3 {
  strings:
    $key_9ed3 = { ca bb [2] be a3 [2] f9 a1 [2] be b0 [2] f0 bc [2] fc b6 [2] eb bd [2] f0 f3 [2] cd }

  condition:
    any of them
}