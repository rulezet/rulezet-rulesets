rule TTP_XOR_MULT_DOSStub_9986 {
  strings:
    $key_9986 = { cd ee [2] b9 f6 [2] fe f4 [2] b9 e5 [2] f7 e9 [2] fb e3 [2] ec e8 [2] f7 a6 [2] ca }

  condition:
    any of them
}