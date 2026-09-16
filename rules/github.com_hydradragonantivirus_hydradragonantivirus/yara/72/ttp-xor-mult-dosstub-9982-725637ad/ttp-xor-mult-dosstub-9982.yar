rule TTP_XOR_MULT_DOSStub_9982 {
  strings:
    $key_9982 = { cd ea [2] b9 f2 [2] fe f0 [2] b9 e1 [2] f7 ed [2] fb e7 [2] ec ec [2] f7 a2 [2] ca }

  condition:
    any of them
}