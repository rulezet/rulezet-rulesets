rule TTP_XOR_MULT_DOSStub_94f7 {
  strings:
    $key_94f7 = { c0 9f [2] b4 87 [2] f3 85 [2] b4 94 [2] fa 98 [2] f6 92 [2] e1 99 [2] fa d7 [2] c7 }

  condition:
    any of them
}