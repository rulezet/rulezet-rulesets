rule TTP_XOR_MULT_DOSStub_9942 {
  strings:
    $key_9942 = { cd 2a [2] b9 32 [2] fe 30 [2] b9 21 [2] f7 2d [2] fb 27 [2] ec 2c [2] f7 62 [2] ca }

  condition:
    any of them
}