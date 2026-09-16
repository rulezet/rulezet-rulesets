rule TTP_XOR_MULT_DOSStub_9919 {
  strings:
    $key_9919 = { cd 71 [2] b9 69 [2] fe 6b [2] b9 7a [2] f7 76 [2] fb 7c [2] ec 77 [2] f7 39 [2] ca }

  condition:
    any of them
}