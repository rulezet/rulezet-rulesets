rule TTP_XOR_MULT_DOSStub_99b9 {
  strings:
    $key_99b9 = { cd d1 [2] b9 c9 [2] fe cb [2] b9 da [2] f7 d6 [2] fb dc [2] ec d7 [2] f7 99 [2] ca }

  condition:
    any of them
}