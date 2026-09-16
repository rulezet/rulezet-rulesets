rule TTP_XOR_MULT_DOSStub_9941 {
  strings:
    $key_9941 = { cd 29 [2] b9 31 [2] fe 33 [2] b9 22 [2] f7 2e [2] fb 24 [2] ec 2f [2] f7 61 [2] ca }

  condition:
    any of them
}