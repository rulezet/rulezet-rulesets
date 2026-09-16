rule TTP_XOR_MULT_DOSStub_9969 {
  strings:
    $key_9969 = { cd 01 [2] b9 19 [2] fe 1b [2] b9 0a [2] f7 06 [2] fb 0c [2] ec 07 [2] f7 49 [2] ca }

  condition:
    any of them
}