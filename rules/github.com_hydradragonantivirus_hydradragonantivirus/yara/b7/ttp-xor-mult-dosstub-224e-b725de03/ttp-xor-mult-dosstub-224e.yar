rule TTP_XOR_MULT_DOSStub_224e {
  strings:
    $key_224e = { 76 26 [2] 02 3e [2] 45 3c [2] 02 2d [2] 4c 21 [2] 40 2b [2] 57 20 [2] 4c 6e [2] 71 }

  condition:
    any of them
}