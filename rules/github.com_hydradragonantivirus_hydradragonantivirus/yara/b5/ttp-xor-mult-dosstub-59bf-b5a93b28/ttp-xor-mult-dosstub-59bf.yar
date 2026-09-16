rule TTP_XOR_MULT_DOSStub_59bf {
  strings:
    $key_59bf = { 0d d7 [2] 79 cf [2] 3e cd [2] 79 dc [2] 37 d0 [2] 3b da [2] 2c d1 [2] 37 9f [2] 0a }

  condition:
    any of them
}