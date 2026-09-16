rule TTP_XOR_MULT_DOSStub_9efe {
  strings:
    $key_9efe = { ca 96 [2] be 8e [2] f9 8c [2] be 9d [2] f0 91 [2] fc 9b [2] eb 90 [2] f0 de [2] cd }

  condition:
    any of them
}