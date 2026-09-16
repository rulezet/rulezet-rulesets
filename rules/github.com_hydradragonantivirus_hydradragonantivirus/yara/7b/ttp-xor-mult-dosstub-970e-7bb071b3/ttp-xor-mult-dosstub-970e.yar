rule TTP_XOR_MULT_DOSStub_970e {
  strings:
    $key_970e = { c3 66 [2] b7 7e [2] f0 7c [2] b7 6d [2] f9 61 [2] f5 6b [2] e2 60 [2] f9 2e [2] c4 }

  condition:
    any of them
}