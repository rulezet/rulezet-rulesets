rule TTP_XOR_MULT_DOSStub_85f8 {
  strings:
    $key_85f8 = { d1 90 [2] a5 88 [2] e2 8a [2] a5 9b [2] eb 97 [2] e7 9d [2] f0 96 [2] eb d8 [2] d6 }

  condition:
    any of them
}