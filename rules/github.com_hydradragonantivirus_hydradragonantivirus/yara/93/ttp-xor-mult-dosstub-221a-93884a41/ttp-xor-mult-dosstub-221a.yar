rule TTP_XOR_MULT_DOSStub_221a {
  strings:
    $key_221a = { 76 72 [2] 02 6a [2] 45 68 [2] 02 79 [2] 4c 75 [2] 40 7f [2] 57 74 [2] 4c 3a [2] 71 }

  condition:
    any of them
}