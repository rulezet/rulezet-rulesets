rule TTP_XOR_MULT_DOSStub_8b4d {
  strings:
    $key_8b4d = { df 25 [2] ab 3d [2] ec 3f [2] ab 2e [2] e5 22 [2] e9 28 [2] fe 23 [2] e5 6d [2] d8 }

  condition:
    any of them
}