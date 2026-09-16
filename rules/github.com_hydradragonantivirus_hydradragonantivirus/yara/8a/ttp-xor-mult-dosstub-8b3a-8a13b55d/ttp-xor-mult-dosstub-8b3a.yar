rule TTP_XOR_MULT_DOSStub_8b3a {
  strings:
    $key_8b3a = { df 52 [2] ab 4a [2] ec 48 [2] ab 59 [2] e5 55 [2] e9 5f [2] fe 54 [2] e5 1a [2] d8 }

  condition:
    any of them
}