rule TTP_XOR_MULT_DOSStub_99a5 {
  strings:
    $key_99a5 = { cd cd [2] b9 d5 [2] fe d7 [2] b9 c6 [2] f7 ca [2] fb c0 [2] ec cb [2] f7 85 [2] ca }

  condition:
    any of them
}