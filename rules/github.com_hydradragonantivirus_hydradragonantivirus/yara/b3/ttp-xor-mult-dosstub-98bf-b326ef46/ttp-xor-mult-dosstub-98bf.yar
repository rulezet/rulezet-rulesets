rule TTP_XOR_MULT_DOSStub_98bf {
  strings:
    $key_98bf = { cc d7 [2] b8 cf [2] ff cd [2] b8 dc [2] f6 d0 [2] fa da [2] ed d1 [2] f6 9f [2] cb }

  condition:
    any of them
}