rule TTP_XOR_MULT_DOSStub_99d3 {
  strings:
    $key_99d3 = { cd bb [2] b9 a3 [2] fe a1 [2] b9 b0 [2] f7 bc [2] fb b6 [2] ec bd [2] f7 f3 [2] ca }

  condition:
    any of them
}