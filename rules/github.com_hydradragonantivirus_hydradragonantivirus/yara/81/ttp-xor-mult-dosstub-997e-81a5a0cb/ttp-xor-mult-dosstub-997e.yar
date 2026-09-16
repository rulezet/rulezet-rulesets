rule TTP_XOR_MULT_DOSStub_997e {
  strings:
    $key_997e = { cd 16 [2] b9 0e [2] fe 0c [2] b9 1d [2] f7 11 [2] fb 1b [2] ec 10 [2] f7 5e [2] ca }

  condition:
    any of them
}