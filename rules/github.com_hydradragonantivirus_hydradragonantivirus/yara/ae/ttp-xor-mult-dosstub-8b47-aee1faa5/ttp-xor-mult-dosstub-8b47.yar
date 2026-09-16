rule TTP_XOR_MULT_DOSStub_8b47 {
  strings:
    $key_8b47 = { df 2f [2] ab 37 [2] ec 35 [2] ab 24 [2] e5 28 [2] e9 22 [2] fe 29 [2] e5 67 [2] d8 }

  condition:
    any of them
}