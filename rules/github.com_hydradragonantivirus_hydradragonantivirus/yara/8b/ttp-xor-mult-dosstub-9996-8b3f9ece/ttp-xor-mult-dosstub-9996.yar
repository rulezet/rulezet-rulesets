rule TTP_XOR_MULT_DOSStub_9996 {
  strings:
    $key_9996 = { cd fe [2] b9 e6 [2] fe e4 [2] b9 f5 [2] f7 f9 [2] fb f3 [2] ec f8 [2] f7 b6 [2] ca }

  condition:
    any of them
}