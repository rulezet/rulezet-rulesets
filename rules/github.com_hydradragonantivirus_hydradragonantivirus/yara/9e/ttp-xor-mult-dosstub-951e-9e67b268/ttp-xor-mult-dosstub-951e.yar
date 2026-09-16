rule TTP_XOR_MULT_DOSStub_951e {
  strings:
    $key_951e = { c1 76 [2] b5 6e [2] f2 6c [2] b5 7d [2] fb 71 [2] f7 7b [2] e0 70 [2] fb 3e [2] c6 }

  condition:
    any of them
}