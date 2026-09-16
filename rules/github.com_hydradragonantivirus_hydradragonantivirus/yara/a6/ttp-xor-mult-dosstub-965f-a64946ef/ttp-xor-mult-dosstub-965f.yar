rule TTP_XOR_MULT_DOSStub_965f {
  strings:
    $key_965f = { c2 37 [2] b6 2f [2] f1 2d [2] b6 3c [2] f8 30 [2] f4 3a [2] e3 31 [2] f8 7f [2] c5 }

  condition:
    any of them
}