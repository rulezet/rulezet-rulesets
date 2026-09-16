rule TTP_XOR_MULT_DOSStub_8364 {
  strings:
    $key_8364 = { d7 0c [2] a3 14 [2] e4 16 [2] a3 07 [2] ed 0b [2] e1 01 [2] f6 0a [2] ed 44 [2] d0 }

  condition:
    any of them
}