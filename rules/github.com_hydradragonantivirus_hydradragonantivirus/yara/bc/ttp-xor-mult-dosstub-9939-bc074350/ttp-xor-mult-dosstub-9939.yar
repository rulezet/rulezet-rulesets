rule TTP_XOR_MULT_DOSStub_9939 {
  strings:
    $key_9939 = { cd 51 [2] b9 49 [2] fe 4b [2] b9 5a [2] f7 56 [2] fb 5c [2] ec 57 [2] f7 19 [2] ca }

  condition:
    any of them
}