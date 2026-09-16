rule TTP_XOR_MULT_DOSStub_837c {
  strings:
    $key_837c = { d7 14 [2] a3 0c [2] e4 0e [2] a3 1f [2] ed 13 [2] e1 19 [2] f6 12 [2] ed 5c [2] d0 }

  condition:
    any of them
}