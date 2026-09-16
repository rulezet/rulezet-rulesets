rule TTP_XOR_MULT_DOSStub_9913 {
  strings:
    $key_9913 = { cd 7b [2] b9 63 [2] fe 61 [2] b9 70 [2] f7 7c [2] fb 76 [2] ec 7d [2] f7 33 [2] ca }

  condition:
    any of them
}