rule TTP_XOR_MULT_DOSStub_994f {
  strings:
    $key_994f = { cd 27 [2] b9 3f [2] fe 3d [2] b9 2c [2] f7 20 [2] fb 2a [2] ec 21 [2] f7 6f [2] ca }

  condition:
    any of them
}