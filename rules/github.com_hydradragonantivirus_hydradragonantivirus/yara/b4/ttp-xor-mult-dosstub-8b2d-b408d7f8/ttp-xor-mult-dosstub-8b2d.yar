rule TTP_XOR_MULT_DOSStub_8b2d {
  strings:
    $key_8b2d = { df 45 [2] ab 5d [2] ec 5f [2] ab 4e [2] e5 42 [2] e9 48 [2] fe 43 [2] e5 0d [2] d8 }

  condition:
    any of them
}