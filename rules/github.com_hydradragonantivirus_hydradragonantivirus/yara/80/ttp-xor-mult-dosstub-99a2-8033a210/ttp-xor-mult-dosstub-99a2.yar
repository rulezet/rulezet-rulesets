rule TTP_XOR_MULT_DOSStub_99a2 {
  strings:
    $key_99a2 = { cd ca [2] b9 d2 [2] fe d0 [2] b9 c1 [2] f7 cd [2] fb c7 [2] ec cc [2] f7 82 [2] ca }

  condition:
    any of them
}