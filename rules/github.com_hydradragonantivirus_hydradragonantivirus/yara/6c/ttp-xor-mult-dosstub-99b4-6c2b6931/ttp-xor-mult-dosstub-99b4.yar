rule TTP_XOR_MULT_DOSStub_99b4 {
  strings:
    $key_99b4 = { cd dc [2] b9 c4 [2] fe c6 [2] b9 d7 [2] f7 db [2] fb d1 [2] ec da [2] f7 94 [2] ca }

  condition:
    any of them
}