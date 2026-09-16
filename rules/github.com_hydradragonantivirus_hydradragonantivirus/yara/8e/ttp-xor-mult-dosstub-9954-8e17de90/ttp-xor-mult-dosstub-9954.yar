rule TTP_XOR_MULT_DOSStub_9954 {
  strings:
    $key_9954 = { cd 3c [2] b9 24 [2] fe 26 [2] b9 37 [2] f7 3b [2] fb 31 [2] ec 3a [2] f7 74 [2] ca }

  condition:
    any of them
}