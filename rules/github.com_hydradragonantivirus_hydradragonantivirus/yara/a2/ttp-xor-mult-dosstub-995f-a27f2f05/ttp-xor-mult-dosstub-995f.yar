rule TTP_XOR_MULT_DOSStub_995f {
  strings:
    $key_995f = { cd 37 [2] b9 2f [2] fe 2d [2] b9 3c [2] f7 30 [2] fb 3a [2] ec 31 [2] f7 7f [2] ca }

  condition:
    any of them
}