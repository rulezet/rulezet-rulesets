rule TTP_XOR_MULT_DOSStub_9978 {
  strings:
    $key_9978 = { cd 10 [2] b9 08 [2] fe 0a [2] b9 1b [2] f7 17 [2] fb 1d [2] ec 16 [2] f7 58 [2] ca }

  condition:
    any of them
}