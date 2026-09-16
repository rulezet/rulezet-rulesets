rule TTP_XOR_MULT_DOSStub_d8bf {
  strings:
    $key_d8bf = { 8c d7 [2] f8 cf [2] bf cd [2] f8 dc [2] b6 d0 [2] ba da [2] ad d1 [2] b6 9f [2] 8b }

  condition:
    any of them
}