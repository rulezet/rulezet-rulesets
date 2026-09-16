rule TTP_XOR_MULT_DOSStub_9ebf {
  strings:
    $key_9ebf = { ca d7 [2] be cf [2] f9 cd [2] be dc [2] f0 d0 [2] fc da [2] eb d1 [2] f0 9f [2] cd }

  condition:
    any of them
}