rule TTP_XOR_MULT_DOSStub_901f {
  strings:
    $key_901f = { c4 77 [2] b0 6f [2] f7 6d [2] b0 7c [2] fe 70 [2] f2 7a [2] e5 71 [2] fe 3f [2] c3 }

  condition:
    any of them
}