rule TTP_XOR_MULT_DOSStub_9eb8 {
  strings:
    $key_9eb8 = { ca d0 [2] be c8 [2] f9 ca [2] be db [2] f0 d7 [2] fc dd [2] eb d6 [2] f0 98 [2] cd }

  condition:
    any of them
}