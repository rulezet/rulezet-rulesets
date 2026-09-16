rule TTP_XOR_MULT_DOSStub_8b57 {
  strings:
    $key_8b57 = { df 3f [2] ab 27 [2] ec 25 [2] ab 34 [2] e5 38 [2] e9 32 [2] fe 39 [2] e5 77 [2] d8 }

  condition:
    any of them
}