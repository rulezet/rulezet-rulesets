rule TTP_XOR_MULT_DOSStub_94f5 {
  strings:
    $key_94f5 = { c0 9d [2] b4 85 [2] f3 87 [2] b4 96 [2] fa 9a [2] f6 90 [2] e1 9b [2] fa d5 [2] c7 }

  condition:
    any of them
}