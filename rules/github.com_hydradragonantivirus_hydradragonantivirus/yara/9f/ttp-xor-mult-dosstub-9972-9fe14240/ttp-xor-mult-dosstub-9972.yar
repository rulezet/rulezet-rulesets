rule TTP_XOR_MULT_DOSStub_9972 {
  strings:
    $key_9972 = { cd 1a [2] b9 02 [2] fe 00 [2] b9 11 [2] f7 1d [2] fb 17 [2] ec 1c [2] f7 52 [2] ca }

  condition:
    any of them
}