rule TTP_XOR_MULT_DOSStub_992c {
  strings:
    $key_992c = { cd 44 [2] b9 5c [2] fe 5e [2] b9 4f [2] f7 43 [2] fb 49 [2] ec 42 [2] f7 0c [2] ca }

  condition:
    any of them
}