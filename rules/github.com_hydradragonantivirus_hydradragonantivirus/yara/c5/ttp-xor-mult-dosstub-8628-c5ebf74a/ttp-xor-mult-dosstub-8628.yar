rule TTP_XOR_MULT_DOSStub_8628 {
  strings:
    $key_8628 = { d2 40 [2] a6 58 [2] e1 5a [2] a6 4b [2] e8 47 [2] e4 4d [2] f3 46 [2] e8 08 [2] d5 }

  condition:
    any of them
}