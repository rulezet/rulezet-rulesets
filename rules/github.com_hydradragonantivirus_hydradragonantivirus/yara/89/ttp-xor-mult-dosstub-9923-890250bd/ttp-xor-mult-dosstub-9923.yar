rule TTP_XOR_MULT_DOSStub_9923 {
  strings:
    $key_9923 = { cd 4b [2] b9 53 [2] fe 51 [2] b9 40 [2] f7 4c [2] fb 46 [2] ec 4d [2] f7 03 [2] ca }

  condition:
    any of them
}