rule TTP_XOR_MULT_DOSStub_9912 {
  strings:
    $key_9912 = { cd 7a [2] b9 62 [2] fe 60 [2] b9 71 [2] f7 7d [2] fb 77 [2] ec 7c [2] f7 32 [2] ca }

  condition:
    any of them
}