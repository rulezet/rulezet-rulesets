rule TTP_XOR_MULT_DOSStub_906f {
  strings:
    $key_906f = { c4 07 [2] b0 1f [2] f7 1d [2] b0 0c [2] fe 00 [2] f2 0a [2] e5 01 [2] fe 4f [2] c3 }

  condition:
    any of them
}