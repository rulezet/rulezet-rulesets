rule TTP_XOR_MULT_DOSStub_993a {
  strings:
    $key_993a = { cd 52 [2] b9 4a [2] fe 48 [2] b9 59 [2] f7 55 [2] fb 5f [2] ec 54 [2] f7 1a [2] ca }

  condition:
    any of them
}