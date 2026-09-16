rule TTP_XOR_MULT_DOSStub_9eab {
  strings:
    $key_9eab = { ca c3 [2] be db [2] f9 d9 [2] be c8 [2] f0 c4 [2] fc ce [2] eb c5 [2] f0 8b [2] cd }

  condition:
    any of them
}