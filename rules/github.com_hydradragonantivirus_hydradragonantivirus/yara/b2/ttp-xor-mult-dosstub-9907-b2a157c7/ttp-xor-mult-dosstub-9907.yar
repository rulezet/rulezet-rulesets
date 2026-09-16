rule TTP_XOR_MULT_DOSStub_9907 {
  strings:
    $key_9907 = { cd 6f [2] b9 77 [2] fe 75 [2] b9 64 [2] f7 68 [2] fb 62 [2] ec 69 [2] f7 27 [2] ca }

  condition:
    any of them
}