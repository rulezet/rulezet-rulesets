rule TTP_XOR_MULT_DOSStub_8b4a {
  strings:
    $key_8b4a = { df 22 [2] ab 3a [2] ec 38 [2] ab 29 [2] e5 25 [2] e9 2f [2] fe 24 [2] e5 6a [2] d8 }

  condition:
    any of them
}