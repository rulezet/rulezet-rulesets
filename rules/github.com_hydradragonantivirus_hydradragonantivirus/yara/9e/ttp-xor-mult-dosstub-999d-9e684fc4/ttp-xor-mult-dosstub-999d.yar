rule TTP_XOR_MULT_DOSStub_999d {
  strings:
    $key_999d = { cd f5 [2] b9 ed [2] fe ef [2] b9 fe [2] f7 f2 [2] fb f8 [2] ec f3 [2] f7 bd [2] ca }

  condition:
    any of them
}