rule TTP_XOR_MULT_DOSStub_99d5 {
  strings:
    $key_99d5 = { cd bd [2] b9 a5 [2] fe a7 [2] b9 b6 [2] f7 ba [2] fb b0 [2] ec bb [2] f7 f5 [2] ca }

  condition:
    any of them
}