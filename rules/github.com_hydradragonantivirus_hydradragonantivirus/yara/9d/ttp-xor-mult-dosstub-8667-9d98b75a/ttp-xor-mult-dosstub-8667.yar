rule TTP_XOR_MULT_DOSStub_8667 {
  strings:
    $key_8667 = { d2 0f [2] a6 17 [2] e1 15 [2] a6 04 [2] e8 08 [2] e4 02 [2] f3 09 [2] e8 47 [2] d5 }

  condition:
    any of them
}