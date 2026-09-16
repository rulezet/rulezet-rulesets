rule TTP_XOR_MULT_DOSStub_8b15 {
  strings:
    $key_8b15 = { df 7d [2] ab 65 [2] ec 67 [2] ab 76 [2] e5 7a [2] e9 70 [2] fe 7b [2] e5 35 [2] d8 }

  condition:
    any of them
}