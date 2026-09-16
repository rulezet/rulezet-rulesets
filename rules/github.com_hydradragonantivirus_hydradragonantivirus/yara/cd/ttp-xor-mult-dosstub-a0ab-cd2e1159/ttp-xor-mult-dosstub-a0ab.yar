rule TTP_XOR_MULT_DOSStub_a0ab {
  strings:
    $key_a0ab = { f4 c3 [2] 80 db [2] c7 d9 [2] 80 c8 [2] ce c4 [2] c2 ce [2] d5 c5 [2] ce 8b [2] f3 }

  condition:
    any of them
}