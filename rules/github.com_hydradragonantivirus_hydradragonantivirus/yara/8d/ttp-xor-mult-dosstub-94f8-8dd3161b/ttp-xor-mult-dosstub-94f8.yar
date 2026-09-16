rule TTP_XOR_MULT_DOSStub_94f8 {
  strings:
    $key_94f8 = { c0 90 [2] b4 88 [2] f3 8a [2] b4 9b [2] fa 97 [2] f6 9d [2] e1 96 [2] fa d8 [2] c7 }

  condition:
    any of them
}