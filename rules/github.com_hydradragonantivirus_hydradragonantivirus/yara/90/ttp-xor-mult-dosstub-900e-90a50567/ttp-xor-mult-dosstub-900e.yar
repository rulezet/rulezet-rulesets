rule TTP_XOR_MULT_DOSStub_900e {
  strings:
    $key_900e = { c4 66 [2] b0 7e [2] f7 7c [2] b0 6d [2] fe 61 [2] f2 6b [2] e5 60 [2] fe 2e [2] c3 }

  condition:
    any of them
}