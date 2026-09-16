rule TTP_XOR_MULT_DOSStub_9973 {
  strings:
    $key_9973 = { cd 1b [2] b9 03 [2] fe 01 [2] b9 10 [2] f7 1c [2] fb 16 [2] ec 1d [2] f7 53 [2] ca }

  condition:
    any of them
}