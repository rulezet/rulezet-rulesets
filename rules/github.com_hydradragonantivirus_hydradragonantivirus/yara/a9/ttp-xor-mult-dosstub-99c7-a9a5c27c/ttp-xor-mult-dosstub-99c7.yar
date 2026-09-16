rule TTP_XOR_MULT_DOSStub_99c7 {
  strings:
    $key_99c7 = { cd af [2] b9 b7 [2] fe b5 [2] b9 a4 [2] f7 a8 [2] fb a2 [2] ec a9 [2] f7 e7 [2] ca }

  condition:
    any of them
}