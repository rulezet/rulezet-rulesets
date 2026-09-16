rule TTP_XOR_MULT_DOSStub_9925 {
  strings:
    $key_9925 = { cd 4d [2] b9 55 [2] fe 57 [2] b9 46 [2] f7 4a [2] fb 40 [2] ec 4b [2] f7 05 [2] ca }

  condition:
    any of them
}