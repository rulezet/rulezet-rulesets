rule TTP_XOR_MULT_DOSStub_9945 {
  strings:
    $key_9945 = { cd 2d [2] b9 35 [2] fe 37 [2] b9 26 [2] f7 2a [2] fb 20 [2] ec 2b [2] f7 65 [2] ca }

  condition:
    any of them
}