rule TTP_XOR_MULT_DOSStub_711a {
  strings:
    $key_711a = { 25 72 [2] 51 6a [2] 16 68 [2] 51 79 [2] 1f 75 [2] 13 7f [2] 04 74 [2] 1f 3a [2] 22 }

  condition:
    any of them
}