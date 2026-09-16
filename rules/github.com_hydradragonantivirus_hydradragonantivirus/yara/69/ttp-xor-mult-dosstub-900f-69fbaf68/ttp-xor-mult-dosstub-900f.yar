rule TTP_XOR_MULT_DOSStub_900f {
  strings:
    $key_900f = { c4 67 [2] b0 7f [2] f7 7d [2] b0 6c [2] fe 60 [2] f2 6a [2] e5 61 [2] fe 2f [2] c3 }

  condition:
    any of them
}