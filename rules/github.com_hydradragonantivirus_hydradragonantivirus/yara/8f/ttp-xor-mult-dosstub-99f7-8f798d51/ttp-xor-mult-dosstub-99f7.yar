rule TTP_XOR_MULT_DOSStub_99f7 {
  strings:
    $key_99f7 = { cd 9f [2] b9 87 [2] fe 85 [2] b9 94 [2] f7 98 [2] fb 92 [2] ec 99 [2] f7 d7 [2] ca }

  condition:
    any of them
}