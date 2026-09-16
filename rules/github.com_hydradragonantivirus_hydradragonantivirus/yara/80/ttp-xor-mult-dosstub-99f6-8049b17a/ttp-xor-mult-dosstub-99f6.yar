rule TTP_XOR_MULT_DOSStub_99f6 {
  strings:
    $key_99f6 = { cd 9e [2] b9 86 [2] fe 84 [2] b9 95 [2] f7 99 [2] fb 93 [2] ec 98 [2] f7 d6 [2] ca }

  condition:
    any of them
}