rule TTP_XOR_MULT_DOSStub_9909 {
  strings:
    $key_9909 = { cd 61 [2] b9 79 [2] fe 7b [2] b9 6a [2] f7 66 [2] fb 6c [2] ec 67 [2] f7 29 [2] ca }

  condition:
    any of them
}