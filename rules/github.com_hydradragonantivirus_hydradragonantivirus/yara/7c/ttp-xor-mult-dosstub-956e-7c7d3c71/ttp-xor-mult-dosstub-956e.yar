rule TTP_XOR_MULT_DOSStub_956e {
  strings:
    $key_956e = { c1 06 [2] b5 1e [2] f2 1c [2] b5 0d [2] fb 01 [2] f7 0b [2] e0 00 [2] fb 4e [2] c6 }

  condition:
    any of them
}