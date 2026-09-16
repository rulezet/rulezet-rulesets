rule TTP_XOR_MULT_DOSStub_8611 {
  strings:
    $key_8611 = { d2 79 [2] a6 61 [2] e1 63 [2] a6 72 [2] e8 7e [2] e4 74 [2] f3 7f [2] e8 31 [2] d5 }

  condition:
    any of them
}