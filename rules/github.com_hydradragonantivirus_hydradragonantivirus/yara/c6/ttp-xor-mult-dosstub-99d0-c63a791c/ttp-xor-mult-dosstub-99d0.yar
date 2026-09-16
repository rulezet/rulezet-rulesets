rule TTP_XOR_MULT_DOSStub_99d0 {
  strings:
    $key_99d0 = { cd b8 [2] b9 a0 [2] fe a2 [2] b9 b3 [2] f7 bf [2] fb b5 [2] ec be [2] f7 f0 [2] ca }

  condition:
    any of them
}