rule TTP_XOR_MULT_DOSStub_004a {
  strings:
    $key_004a = { 54 22 [2] 20 3a [2] 67 38 [2] 20 29 [2] 6e 25 [2] 62 2f [2] 75 24 [2] 6e 6a [2] 53 }

  condition:
    any of them
}