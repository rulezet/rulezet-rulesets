rule TTP_XOR_MULT_DOSStub_99f9 {
  strings:
    $key_99f9 = { cd 91 [2] b9 89 [2] fe 8b [2] b9 9a [2] f7 96 [2] fb 9c [2] ec 97 [2] f7 d9 [2] ca }

  condition:
    any of them
}