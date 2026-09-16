rule TTP_XOR_MULT_DOSStub_99d8 {
  strings:
    $key_99d8 = { cd b0 [2] b9 a8 [2] fe aa [2] b9 bb [2] f7 b7 [2] fb bd [2] ec b6 [2] f7 f8 [2] ca }

  condition:
    any of them
}