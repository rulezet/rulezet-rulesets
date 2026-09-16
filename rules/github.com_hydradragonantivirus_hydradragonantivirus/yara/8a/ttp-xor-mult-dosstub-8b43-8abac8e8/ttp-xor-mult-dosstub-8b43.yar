rule TTP_XOR_MULT_DOSStub_8b43 {
  strings:
    $key_8b43 = { df 2b [2] ab 33 [2] ec 31 [2] ab 20 [2] e5 2c [2] e9 26 [2] fe 2d [2] e5 63 [2] d8 }

  condition:
    any of them
}