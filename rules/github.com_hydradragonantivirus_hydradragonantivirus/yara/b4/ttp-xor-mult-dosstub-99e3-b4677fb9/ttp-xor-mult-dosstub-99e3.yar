rule TTP_XOR_MULT_DOSStub_99e3 {
  strings:
    $key_99e3 = { cd 8b [2] b9 93 [2] fe 91 [2] b9 80 [2] f7 8c [2] fb 86 [2] ec 8d [2] f7 c3 [2] ca }

  condition:
    any of them
}