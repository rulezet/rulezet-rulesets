rule TTP_XOR_MULT_DOSStub_9950 {
  strings:
    $key_9950 = { cd 38 [2] b9 20 [2] fe 22 [2] b9 33 [2] f7 3f [2] fb 35 [2] ec 3e [2] f7 70 [2] ca }

  condition:
    any of them
}