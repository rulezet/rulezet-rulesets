rule TTP_XOR_MULT_DOSStub_99fc {
  strings:
    $key_99fc = { cd 94 [2] b9 8c [2] fe 8e [2] b9 9f [2] f7 93 [2] fb 99 [2] ec 92 [2] f7 dc [2] ca }

  condition:
    any of them
}