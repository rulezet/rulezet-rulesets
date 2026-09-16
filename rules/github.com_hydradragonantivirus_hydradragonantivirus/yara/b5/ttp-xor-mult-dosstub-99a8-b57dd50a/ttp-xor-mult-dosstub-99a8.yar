rule TTP_XOR_MULT_DOSStub_99a8 {
  strings:
    $key_99a8 = { cd c0 [2] b9 d8 [2] fe da [2] b9 cb [2] f7 c7 [2] fb cd [2] ec c6 [2] f7 88 [2] ca }

  condition:
    any of them
}