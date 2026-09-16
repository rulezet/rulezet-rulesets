rule TTP_XOR_MULT_DOSStub_8dbd {
  strings:
    $key_8dbd = { d9 d5 [2] ad cd [2] ea cf [2] ad de [2] e3 d2 [2] ef d8 [2] f8 d3 [2] e3 9d [2] de }

  condition:
    any of them
}