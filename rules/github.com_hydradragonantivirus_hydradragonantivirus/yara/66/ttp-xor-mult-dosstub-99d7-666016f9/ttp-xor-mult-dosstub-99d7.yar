rule TTP_XOR_MULT_DOSStub_99d7 {
  strings:
    $key_99d7 = { cd bf [2] b9 a7 [2] fe a5 [2] b9 b4 [2] f7 b8 [2] fb b2 [2] ec b9 [2] f7 f7 [2] ca }

  condition:
    any of them
}