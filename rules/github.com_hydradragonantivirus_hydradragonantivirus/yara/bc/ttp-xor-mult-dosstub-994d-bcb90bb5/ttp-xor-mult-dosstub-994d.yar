rule TTP_XOR_MULT_DOSStub_994d {
  strings:
    $key_994d = { cd 25 [2] b9 3d [2] fe 3f [2] b9 2e [2] f7 22 [2] fb 28 [2] ec 23 [2] f7 6d [2] ca }

  condition:
    any of them
}