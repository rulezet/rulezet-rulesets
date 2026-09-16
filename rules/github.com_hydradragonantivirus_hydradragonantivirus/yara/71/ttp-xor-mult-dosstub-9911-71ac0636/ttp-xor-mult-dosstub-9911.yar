rule TTP_XOR_MULT_DOSStub_9911 {
  strings:
    $key_9911 = { cd 79 [2] b9 61 [2] fe 63 [2] b9 72 [2] f7 7e [2] fb 74 [2] ec 7f [2] f7 31 [2] ca }

  condition:
    any of them
}