rule TTP_XOR_MULT_DOSStub_99f8 {
  strings:
    $key_99f8 = { cd 90 [2] b9 88 [2] fe 8a [2] b9 9b [2] f7 97 [2] fb 9d [2] ec 96 [2] f7 d8 [2] ca }

  condition:
    any of them
}