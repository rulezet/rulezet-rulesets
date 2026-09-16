rule TTP_XOR_MULT_DOSStub_9968 {
  strings:
    $key_9968 = { cd 00 [2] b9 18 [2] fe 1a [2] b9 0b [2] f7 07 [2] fb 0d [2] ec 06 [2] f7 48 [2] ca }

  condition:
    any of them
}