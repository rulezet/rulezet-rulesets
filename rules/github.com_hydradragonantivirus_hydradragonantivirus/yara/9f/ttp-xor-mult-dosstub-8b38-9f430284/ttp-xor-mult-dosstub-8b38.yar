rule TTP_XOR_MULT_DOSStub_8b38 {
  strings:
    $key_8b38 = { df 50 [2] ab 48 [2] ec 4a [2] ab 5b [2] e5 57 [2] e9 5d [2] fe 56 [2] e5 18 [2] d8 }

  condition:
    any of them
}