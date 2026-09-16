rule TTP_XOR_MULT_DOSStub_99e5 {
  strings:
    $key_99e5 = { cd 8d [2] b9 95 [2] fe 97 [2] b9 86 [2] f7 8a [2] fb 80 [2] ec 8b [2] f7 c5 [2] ca }

  condition:
    any of them
}