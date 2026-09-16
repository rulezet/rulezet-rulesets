rule TTP_XOR_MULT_DOSStub_8b41 {
  strings:
    $key_8b41 = { df 29 [2] ab 31 [2] ec 33 [2] ab 22 [2] e5 2e [2] e9 24 [2] fe 2f [2] e5 61 [2] d8 }

  condition:
    any of them
}