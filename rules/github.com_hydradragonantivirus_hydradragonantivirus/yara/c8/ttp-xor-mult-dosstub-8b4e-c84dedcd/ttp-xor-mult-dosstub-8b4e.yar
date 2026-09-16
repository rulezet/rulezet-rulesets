rule TTP_XOR_MULT_DOSStub_8b4e {
  strings:
    $key_8b4e = { df 26 [2] ab 3e [2] ec 3c [2] ab 2d [2] e5 21 [2] e9 2b [2] fe 20 [2] e5 6e [2] d8 }

  condition:
    any of them
}