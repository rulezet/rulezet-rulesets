rule TTP_XOR_MULT_DOSStub_8b5d {
  strings:
    $key_8b5d = { df 35 [2] ab 2d [2] ec 2f [2] ab 3e [2] e5 32 [2] e9 38 [2] fe 33 [2] e5 7d [2] d8 }

  condition:
    any of them
}