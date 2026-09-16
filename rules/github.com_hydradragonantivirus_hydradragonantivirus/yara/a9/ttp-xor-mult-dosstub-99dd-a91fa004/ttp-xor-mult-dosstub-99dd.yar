rule TTP_XOR_MULT_DOSStub_99dd {
  strings:
    $key_99dd = { cd b5 [2] b9 ad [2] fe af [2] b9 be [2] f7 b2 [2] fb b8 [2] ec b3 [2] f7 fd [2] ca }

  condition:
    any of them
}