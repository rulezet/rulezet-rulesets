rule TTP_XOR_MULT_DOSStub_99f5 {
  strings:
    $key_99f5 = { cd 9d [2] b9 85 [2] fe 87 [2] b9 96 [2] f7 9a [2] fb 90 [2] ec 9b [2] f7 d5 [2] ca }

  condition:
    any of them
}