rule TTP_XOR_MULT_DOSStub_904c {
  strings:
    $key_904c = { c4 24 [2] b0 3c [2] f7 3e [2] b0 2f [2] fe 23 [2] f2 29 [2] e5 22 [2] fe 6c [2] c3 }

  condition:
    any of them
}