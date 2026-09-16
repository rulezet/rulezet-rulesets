rule TTP_XOR_MULT_DOSStub_9930 {
  strings:
    $key_9930 = { cd 58 [2] b9 40 [2] fe 42 [2] b9 53 [2] f7 5f [2] fb 55 [2] ec 5e [2] f7 10 [2] ca }

  condition:
    any of them
}