rule TTP_XOR_MULT_DOSStub_561a {
  strings:
    $key_561a = { 02 72 [2] 76 6a [2] 31 68 [2] 76 79 [2] 38 75 [2] 34 7f [2] 23 74 [2] 38 3a [2] 05 }

  condition:
    any of them
}