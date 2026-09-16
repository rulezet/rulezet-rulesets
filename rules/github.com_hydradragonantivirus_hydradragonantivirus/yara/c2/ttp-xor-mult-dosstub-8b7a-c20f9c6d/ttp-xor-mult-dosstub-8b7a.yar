rule TTP_XOR_MULT_DOSStub_8b7a {
  strings:
    $key_8b7a = { df 12 [2] ab 0a [2] ec 08 [2] ab 19 [2] e5 15 [2] e9 1f [2] fe 14 [2] e5 5a [2] d8 }

  condition:
    any of them
}