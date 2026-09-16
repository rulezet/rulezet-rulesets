rule TTP_XOR_MULT_DOSStub_8336 {
  strings:
    $key_8336 = { d7 5e [2] a3 46 [2] e4 44 [2] a3 55 [2] ed 59 [2] e1 53 [2] f6 58 [2] ed 16 [2] d0 }

  condition:
    any of them
}