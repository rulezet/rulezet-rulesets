rule TTP_XOR_MULT_DOSStub_98bd {
  strings:
    $key_98bd = { cc d5 [2] b8 cd [2] ff cf [2] b8 de [2] f6 d2 [2] fa d8 [2] ed d3 [2] f6 9d [2] cb }

  condition:
    any of them
}