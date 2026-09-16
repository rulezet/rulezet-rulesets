rule TTP_XOR_MULT_DOSStub_99e0 {
  strings:
    $key_99e0 = { cd 88 [2] b9 90 [2] fe 92 [2] b9 83 [2] f7 8f [2] fb 85 [2] ec 8e [2] f7 c0 [2] ca }

  condition:
    any of them
}