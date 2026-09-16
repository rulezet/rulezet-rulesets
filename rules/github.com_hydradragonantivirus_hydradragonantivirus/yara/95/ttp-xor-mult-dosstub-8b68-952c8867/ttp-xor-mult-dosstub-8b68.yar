rule TTP_XOR_MULT_DOSStub_8b68 {
  strings:
    $key_8b68 = { df 00 [2] ab 18 [2] ec 1a [2] ab 0b [2] e5 07 [2] e9 0d [2] fe 06 [2] e5 48 [2] d8 }

  condition:
    any of them
}