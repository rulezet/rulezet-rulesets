rule TTP_XOR_MULT_DOSStub_9932 {
  strings:
    $key_9932 = { cd 5a [2] b9 42 [2] fe 40 [2] b9 51 [2] f7 5d [2] fb 57 [2] ec 5c [2] f7 12 [2] ca }

  condition:
    any of them
}