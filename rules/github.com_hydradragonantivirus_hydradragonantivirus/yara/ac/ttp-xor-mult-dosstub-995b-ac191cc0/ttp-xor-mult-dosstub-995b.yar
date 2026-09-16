rule TTP_XOR_MULT_DOSStub_995b {
  strings:
    $key_995b = { cd 33 [2] b9 2b [2] fe 29 [2] b9 38 [2] f7 34 [2] fb 3e [2] ec 35 [2] f7 7b [2] ca }

  condition:
    any of them
}