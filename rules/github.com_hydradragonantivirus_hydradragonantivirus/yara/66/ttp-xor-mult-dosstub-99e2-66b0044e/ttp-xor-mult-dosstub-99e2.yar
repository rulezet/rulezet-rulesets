rule TTP_XOR_MULT_DOSStub_99e2 {
  strings:
    $key_99e2 = { cd 8a [2] b9 92 [2] fe 90 [2] b9 81 [2] f7 8d [2] fb 87 [2] ec 8c [2] f7 c2 [2] ca }

  condition:
    any of them
}