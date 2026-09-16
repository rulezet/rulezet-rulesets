rule TTP_XOR_MULT_DOSStub_9957 {
  strings:
    $key_9957 = { cd 3f [2] b9 27 [2] fe 25 [2] b9 34 [2] f7 38 [2] fb 32 [2] ec 39 [2] f7 77 [2] ca }

  condition:
    any of them
}