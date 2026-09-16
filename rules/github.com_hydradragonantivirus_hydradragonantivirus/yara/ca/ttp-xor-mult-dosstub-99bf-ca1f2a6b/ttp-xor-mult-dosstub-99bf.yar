rule TTP_XOR_MULT_DOSStub_99bf {
  strings:
    $key_99bf = { cd d7 [2] b9 cf [2] fe cd [2] b9 dc [2] f7 d0 [2] fb da [2] ec d1 [2] f7 9f [2] ca }

  condition:
    any of them
}