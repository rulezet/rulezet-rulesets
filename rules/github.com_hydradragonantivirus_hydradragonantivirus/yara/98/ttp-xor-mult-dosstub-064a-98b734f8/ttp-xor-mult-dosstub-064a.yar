rule TTP_XOR_MULT_DOSStub_064a {
  strings:
    $key_064a = { 52 22 [2] 26 3a [2] 61 38 [2] 26 29 [2] 68 25 [2] 64 2f [2] 73 24 [2] 68 6a [2] 55 }

  condition:
    any of them
}