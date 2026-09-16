rule TTP_XOR_MULT_DOSStub_8b34 {
  strings:
    $key_8b34 = { df 5c [2] ab 44 [2] ec 46 [2] ab 57 [2] e5 5b [2] e9 51 [2] fe 5a [2] e5 14 [2] d8 }

  condition:
    any of them
}