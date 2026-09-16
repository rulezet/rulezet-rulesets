rule TTP_XOR_MULT_DOSStub_9979 {
  strings:
    $key_9979 = { cd 11 [2] b9 09 [2] fe 0b [2] b9 1a [2] f7 16 [2] fb 1c [2] ec 17 [2] f7 59 [2] ca }

  condition:
    any of them
}