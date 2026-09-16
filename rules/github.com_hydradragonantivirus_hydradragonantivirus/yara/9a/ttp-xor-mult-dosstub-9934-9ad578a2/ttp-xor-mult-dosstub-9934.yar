rule TTP_XOR_MULT_DOSStub_9934 {
  strings:
    $key_9934 = { cd 5c [2] b9 44 [2] fe 46 [2] b9 57 [2] f7 5b [2] fb 51 [2] ec 5a [2] f7 14 [2] ca }

  condition:
    any of them
}