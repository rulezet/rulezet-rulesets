rule TTP_XOR_MULT_DOSStub_d9bf {
  strings:
    $key_d9bf = { 8d d7 [2] f9 cf [2] be cd [2] f9 dc [2] b7 d0 [2] bb da [2] ac d1 [2] b7 9f [2] 8a }

  condition:
    any of them
}