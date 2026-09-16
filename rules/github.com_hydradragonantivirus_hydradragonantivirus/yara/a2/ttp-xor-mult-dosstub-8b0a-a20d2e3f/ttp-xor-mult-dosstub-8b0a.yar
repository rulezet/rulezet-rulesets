rule TTP_XOR_MULT_DOSStub_8b0a {
  strings:
    $key_8b0a = { df 62 [2] ab 7a [2] ec 78 [2] ab 69 [2] e5 65 [2] e9 6f [2] fe 64 [2] e5 2a [2] d8 }

  condition:
    any of them
}