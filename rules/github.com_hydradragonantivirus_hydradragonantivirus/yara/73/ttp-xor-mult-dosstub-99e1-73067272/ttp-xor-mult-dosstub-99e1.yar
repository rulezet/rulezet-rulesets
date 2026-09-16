rule TTP_XOR_MULT_DOSStub_99e1 {
  strings:
    $key_99e1 = { cd 89 [2] b9 91 [2] fe 93 [2] b9 82 [2] f7 8e [2] fb 84 [2] ec 8f [2] f7 c1 [2] ca }

  condition:
    any of them
}