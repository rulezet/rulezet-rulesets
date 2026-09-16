rule TTP_XOR_MULT_DOSStub_8b65 {
  strings:
    $key_8b65 = { df 0d [2] ab 15 [2] ec 17 [2] ab 06 [2] e5 0a [2] e9 00 [2] fe 0b [2] e5 45 [2] d8 }

  condition:
    any of them
}