rule TTP_XOR_MULT_DOSStub_9944 {
  strings:
    $key_9944 = { cd 2c [2] b9 34 [2] fe 36 [2] b9 27 [2] f7 2b [2] fb 21 [2] ec 2a [2] f7 64 [2] ca }

  condition:
    any of them
}