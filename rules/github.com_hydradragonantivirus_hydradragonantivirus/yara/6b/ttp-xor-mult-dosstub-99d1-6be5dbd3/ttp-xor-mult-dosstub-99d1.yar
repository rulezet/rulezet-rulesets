rule TTP_XOR_MULT_DOSStub_99d1 {
  strings:
    $key_99d1 = { cd b9 [2] b9 a1 [2] fe a3 [2] b9 b2 [2] f7 be [2] fb b4 [2] ec bf [2] f7 f1 [2] ca }

  condition:
    any of them
}