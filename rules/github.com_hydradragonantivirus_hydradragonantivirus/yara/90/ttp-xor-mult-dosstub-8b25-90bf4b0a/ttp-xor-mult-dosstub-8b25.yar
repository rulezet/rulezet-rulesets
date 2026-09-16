rule TTP_XOR_MULT_DOSStub_8b25 {
  strings:
    $key_8b25 = { df 4d [2] ab 55 [2] ec 57 [2] ab 46 [2] e5 4a [2] e9 40 [2] fe 4b [2] e5 05 [2] d8 }

  condition:
    any of them
}