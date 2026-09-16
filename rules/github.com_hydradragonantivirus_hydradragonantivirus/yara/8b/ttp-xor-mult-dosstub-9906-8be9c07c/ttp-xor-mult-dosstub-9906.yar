rule TTP_XOR_MULT_DOSStub_9906 {
  strings:
    $key_9906 = { cd 6e [2] b9 76 [2] fe 74 [2] b9 65 [2] f7 69 [2] fb 63 [2] ec 68 [2] f7 26 [2] ca }

  condition:
    any of them
}