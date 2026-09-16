rule TTP_XOR_MULT_DOSStub_8b7d {
  strings:
    $key_8b7d = { df 15 [2] ab 0d [2] ec 0f [2] ab 1e [2] e5 12 [2] e9 18 [2] fe 13 [2] e5 5d [2] d8 }

  condition:
    any of them
}