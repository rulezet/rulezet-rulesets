rule TTP_XOR_MULT_DOSStub_9946 {
  strings:
    $key_9946 = { cd 2e [2] b9 36 [2] fe 34 [2] b9 25 [2] f7 29 [2] fb 23 [2] ec 28 [2] f7 66 [2] ca }

  condition:
    any of them
}