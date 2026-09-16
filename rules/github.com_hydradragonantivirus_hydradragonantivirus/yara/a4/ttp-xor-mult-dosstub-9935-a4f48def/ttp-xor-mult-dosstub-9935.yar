rule TTP_XOR_MULT_DOSStub_9935 {
  strings:
    $key_9935 = { cd 5d [2] b9 45 [2] fe 47 [2] b9 56 [2] f7 5a [2] fb 50 [2] ec 5b [2] f7 15 [2] ca }

  condition:
    any of them
}