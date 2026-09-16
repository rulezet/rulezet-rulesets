rule TTP_XOR_MULT_DOSStub_9984 {
  strings:
    $key_9984 = { cd ec [2] b9 f4 [2] fe f6 [2] b9 e7 [2] f7 eb [2] fb e1 [2] ec ea [2] f7 a4 [2] ca }

  condition:
    any of them
}