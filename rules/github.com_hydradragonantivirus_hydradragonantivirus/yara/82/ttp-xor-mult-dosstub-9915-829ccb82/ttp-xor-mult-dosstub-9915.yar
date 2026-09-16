rule TTP_XOR_MULT_DOSStub_9915 {
  strings:
    $key_9915 = { cd 7d [2] b9 65 [2] fe 67 [2] b9 76 [2] f7 7a [2] fb 70 [2] ec 7b [2] f7 35 [2] ca }

  condition:
    any of them
}