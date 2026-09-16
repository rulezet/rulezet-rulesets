rule TTP_XOR_MULT_DOSStub_9938 {
  strings:
    $key_9938 = { cd 50 [2] b9 48 [2] fe 4a [2] b9 5b [2] f7 57 [2] fb 5d [2] ec 56 [2] f7 18 [2] ca }

  condition:
    any of them
}