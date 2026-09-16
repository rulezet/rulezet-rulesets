rule TTP_XOR_MULT_DOSStub_8b77 {
  strings:
    $key_8b77 = { df 1f [2] ab 07 [2] ec 05 [2] ab 14 [2] e5 18 [2] e9 12 [2] fe 19 [2] e5 57 [2] d8 }

  condition:
    any of them
}