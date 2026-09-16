rule TTP_XOR_MULT_DOSStub_a1ab {
  strings:
    $key_a1ab = { f5 c3 [2] 81 db [2] c6 d9 [2] 81 c8 [2] cf c4 [2] c3 ce [2] d4 c5 [2] cf 8b [2] f2 }

  condition:
    any of them
}