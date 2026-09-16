rule TTP_XOR_MULT_DOSStub_996b {
  strings:
    $key_996b = { cd 03 [2] b9 1b [2] fe 19 [2] b9 08 [2] f7 04 [2] fb 0e [2] ec 05 [2] f7 4b [2] ca }

  condition:
    any of them
}