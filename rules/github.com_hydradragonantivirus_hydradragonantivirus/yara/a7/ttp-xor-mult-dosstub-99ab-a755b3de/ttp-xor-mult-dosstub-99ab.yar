rule TTP_XOR_MULT_DOSStub_99ab {
  strings:
    $key_99ab = { cd c3 [2] b9 db [2] fe d9 [2] b9 c8 [2] f7 c4 [2] fb ce [2] ec c5 [2] f7 8b [2] ca }

  condition:
    any of them
}