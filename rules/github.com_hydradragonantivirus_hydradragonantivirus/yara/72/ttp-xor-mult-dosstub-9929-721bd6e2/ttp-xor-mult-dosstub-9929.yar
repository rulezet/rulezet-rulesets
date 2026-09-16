rule TTP_XOR_MULT_DOSStub_9929 {
  strings:
    $key_9929 = { cd 41 [2] b9 59 [2] fe 5b [2] b9 4a [2] f7 46 [2] fb 4c [2] ec 47 [2] f7 09 [2] ca }

  condition:
    any of them
}