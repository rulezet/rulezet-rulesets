rule TTP_XOR_MULT_DOSStub_905c {
  strings:
    $key_905c = { c4 34 [2] b0 2c [2] f7 2e [2] b0 3f [2] fe 33 [2] f2 39 [2] e5 32 [2] fe 7c [2] c3 }

  condition:
    any of them
}