rule TTP_XOR_MULT_DOSStub_991f {
  strings:
    $key_991f = { cd 77 [2] b9 6f [2] fe 6d [2] b9 7c [2] f7 70 [2] fb 7a [2] ec 71 [2] f7 3f [2] ca }

  condition:
    any of them
}