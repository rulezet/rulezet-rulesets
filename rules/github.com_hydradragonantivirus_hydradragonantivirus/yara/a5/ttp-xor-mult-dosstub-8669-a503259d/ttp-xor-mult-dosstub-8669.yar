rule TTP_XOR_MULT_DOSStub_8669 {
  strings:
    $key_8669 = { d2 01 [2] a6 19 [2] e1 1b [2] a6 0a [2] e8 06 [2] e4 0c [2] f3 07 [2] e8 49 [2] d5 }

  condition:
    any of them
}