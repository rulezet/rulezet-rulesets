rule TTP_XOR_MULT_DOSStub_8b48 {
  strings:
    $key_8b48 = { df 20 [2] ab 38 [2] ec 3a [2] ab 2b [2] e5 27 [2] e9 2d [2] fe 26 [2] e5 68 [2] d8 }

  condition:
    any of them
}