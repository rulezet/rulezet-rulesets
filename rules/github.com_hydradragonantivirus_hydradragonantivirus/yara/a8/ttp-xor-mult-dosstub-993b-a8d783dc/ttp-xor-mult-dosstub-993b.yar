rule TTP_XOR_MULT_DOSStub_993b {
  strings:
    $key_993b = { cd 53 [2] b9 4b [2] fe 49 [2] b9 58 [2] f7 54 [2] fb 5e [2] ec 55 [2] f7 1b [2] ca }

  condition:
    any of them
}