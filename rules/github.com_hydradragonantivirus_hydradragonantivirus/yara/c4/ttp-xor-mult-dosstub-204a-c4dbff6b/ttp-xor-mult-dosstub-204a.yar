rule TTP_XOR_MULT_DOSStub_204a {
  strings:
    $key_204a = { 74 22 [2] 00 3a [2] 47 38 [2] 00 29 [2] 4e 25 [2] 42 2f [2] 55 24 [2] 4e 6a [2] 73 }

  condition:
    any of them
}