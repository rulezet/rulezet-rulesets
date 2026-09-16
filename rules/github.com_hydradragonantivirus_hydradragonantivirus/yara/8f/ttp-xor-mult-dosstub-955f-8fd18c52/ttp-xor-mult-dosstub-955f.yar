rule TTP_XOR_MULT_DOSStub_955f {
  strings:
    $key_955f = { c1 37 [2] b5 2f [2] f2 2d [2] b5 3c [2] fb 30 [2] f7 3a [2] e0 31 [2] fb 7f [2] c6 }

  condition:
    any of them
}