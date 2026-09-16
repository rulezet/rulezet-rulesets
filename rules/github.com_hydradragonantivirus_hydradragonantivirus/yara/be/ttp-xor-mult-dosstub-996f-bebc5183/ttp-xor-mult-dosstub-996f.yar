rule TTP_XOR_MULT_DOSStub_996f {
  strings:
    $key_996f = { cd 07 [2] b9 1f [2] fe 1d [2] b9 0c [2] f7 00 [2] fb 0a [2] ec 01 [2] f7 4f [2] ca }

  condition:
    any of them
}