rule TTP_XOR_MULT_DOSStub_9928 {
  strings:
    $key_9928 = { cd 40 [2] b9 58 [2] fe 5a [2] b9 4b [2] f7 47 [2] fb 4d [2] ec 46 [2] f7 08 [2] ca }

  condition:
    any of them
}