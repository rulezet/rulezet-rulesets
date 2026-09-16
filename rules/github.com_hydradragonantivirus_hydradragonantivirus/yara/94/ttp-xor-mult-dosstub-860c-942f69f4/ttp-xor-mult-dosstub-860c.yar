rule TTP_XOR_MULT_DOSStub_860c {
  strings:
    $key_860c = { d2 64 [2] a6 7c [2] e1 7e [2] a6 6f [2] e8 63 [2] e4 69 [2] f3 62 [2] e8 2c [2] d5 }

  condition:
    any of them
}