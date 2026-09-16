rule TTP_XOR_MULT_DOSStub_a8ab {
  strings:
    $key_a8ab = { fc c3 [2] 88 db [2] cf d9 [2] 88 c8 [2] c6 c4 [2] ca ce [2] dd c5 [2] c6 8b [2] fb }

  condition:
    any of them
}