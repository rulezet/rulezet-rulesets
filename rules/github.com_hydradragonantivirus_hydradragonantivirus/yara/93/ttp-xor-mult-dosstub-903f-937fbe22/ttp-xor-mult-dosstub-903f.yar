rule TTP_XOR_MULT_DOSStub_903f {
  strings:
    $key_903f = { c4 57 [2] b0 4f [2] f7 4d [2] b0 5c [2] fe 50 [2] f2 5a [2] e5 51 [2] fe 1f [2] c3 }

  condition:
    any of them
}