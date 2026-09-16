rule TTP_XOR_MULT_DOSStub_9901 {
  strings:
    $key_9901 = { cd 69 [2] b9 71 [2] fe 73 [2] b9 62 [2] f7 6e [2] fb 64 [2] ec 6f [2] f7 21 [2] ca }

  condition:
    any of them
}