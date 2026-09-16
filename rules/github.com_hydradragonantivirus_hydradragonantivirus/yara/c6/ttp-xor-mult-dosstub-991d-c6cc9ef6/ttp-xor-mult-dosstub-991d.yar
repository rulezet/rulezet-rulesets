rule TTP_XOR_MULT_DOSStub_991d {
  strings:
    $key_991d = { cd 75 [2] b9 6d [2] fe 6f [2] b9 7e [2] f7 72 [2] fb 78 [2] ec 73 [2] f7 3d [2] ca }

  condition:
    any of them
}