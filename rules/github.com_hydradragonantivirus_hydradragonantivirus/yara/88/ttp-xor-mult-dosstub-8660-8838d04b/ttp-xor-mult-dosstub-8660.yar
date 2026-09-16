rule TTP_XOR_MULT_DOSStub_8660 {
  strings:
    $key_8660 = { d2 08 [2] a6 10 [2] e1 12 [2] a6 03 [2] e8 0f [2] e4 05 [2] f3 0e [2] e8 40 [2] d5 }

  condition:
    any of them
}