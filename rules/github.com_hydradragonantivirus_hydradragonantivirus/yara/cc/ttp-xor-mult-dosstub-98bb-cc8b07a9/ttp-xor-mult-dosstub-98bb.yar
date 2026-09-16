rule TTP_XOR_MULT_DOSStub_98bb {
  strings:
    $key_98bb = { cc d3 [2] b8 cb [2] ff c9 [2] b8 d8 [2] f6 d4 [2] fa de [2] ed d5 [2] f6 9b [2] cb }

  condition:
    any of them
}