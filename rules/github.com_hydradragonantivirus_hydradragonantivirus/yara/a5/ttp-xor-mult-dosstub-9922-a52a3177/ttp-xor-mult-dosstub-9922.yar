rule TTP_XOR_MULT_DOSStub_9922 {
  strings:
    $key_9922 = { cd 4a [2] b9 52 [2] fe 50 [2] b9 41 [2] f7 4d [2] fb 47 [2] ec 4c [2] f7 02 [2] ca }

  condition:
    any of them
}