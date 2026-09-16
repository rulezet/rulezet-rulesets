rule TTP_XOR_MULT_DOSStub_9904 {
  strings:
    $key_9904 = { cd 6c [2] b9 74 [2] fe 76 [2] b9 67 [2] f7 6b [2] fb 61 [2] ec 6a [2] f7 24 [2] ca }

  condition:
    any of them
}