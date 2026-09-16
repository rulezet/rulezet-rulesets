rule TTP_XOR_MULT_DOSStub_992e {
  strings:
    $key_992e = { cd 46 [2] b9 5e [2] fe 5c [2] b9 4d [2] f7 41 [2] fb 4b [2] ec 40 [2] f7 0e [2] ca }

  condition:
    any of them
}