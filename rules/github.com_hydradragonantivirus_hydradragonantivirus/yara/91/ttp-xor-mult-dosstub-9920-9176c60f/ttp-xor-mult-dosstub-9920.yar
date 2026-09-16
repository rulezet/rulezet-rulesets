rule TTP_XOR_MULT_DOSStub_9920 {
  strings:
    $key_9920 = { cd 48 [2] b9 50 [2] fe 52 [2] b9 43 [2] f7 4f [2] fb 45 [2] ec 4e [2] f7 00 [2] ca }

  condition:
    any of them
}