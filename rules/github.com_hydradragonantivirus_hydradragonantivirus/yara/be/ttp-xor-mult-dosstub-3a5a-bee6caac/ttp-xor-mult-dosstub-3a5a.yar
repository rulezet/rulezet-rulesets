rule TTP_XOR_MULT_DOSStub_3a5a {
  strings:
    $key_3a5a = { 6e 32 [2] 1a 2a [2] 5d 28 [2] 1a 39 [2] 54 35 [2] 58 3f [2] 4f 34 [2] 54 7a [2] 69 }

  condition:
    any of them
}