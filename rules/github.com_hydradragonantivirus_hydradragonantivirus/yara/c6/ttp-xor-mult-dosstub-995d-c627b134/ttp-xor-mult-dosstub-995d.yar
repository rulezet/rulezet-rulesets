rule TTP_XOR_MULT_DOSStub_995d {
  strings:
    $key_995d = { cd 35 [2] b9 2d [2] fe 2f [2] b9 3e [2] f7 32 [2] fb 38 [2] ec 33 [2] f7 7d [2] ca }

  condition:
    any of them
}