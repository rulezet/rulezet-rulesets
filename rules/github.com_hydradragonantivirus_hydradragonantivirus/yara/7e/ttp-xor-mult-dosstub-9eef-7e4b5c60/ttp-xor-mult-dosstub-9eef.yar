rule TTP_XOR_MULT_DOSStub_9eef {
  strings:
    $key_9eef = { ca 87 [2] be 9f [2] f9 9d [2] be 8c [2] f0 80 [2] fc 8a [2] eb 81 [2] f0 cf [2] cd }

  condition:
    any of them
}