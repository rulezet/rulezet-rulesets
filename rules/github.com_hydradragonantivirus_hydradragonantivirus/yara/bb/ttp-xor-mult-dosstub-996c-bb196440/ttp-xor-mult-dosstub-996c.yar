rule TTP_XOR_MULT_DOSStub_996c {
  strings:
    $key_996c = { cd 04 [2] b9 1c [2] fe 1e [2] b9 0f [2] f7 03 [2] fb 09 [2] ec 02 [2] f7 4c [2] ca }

  condition:
    any of them
}