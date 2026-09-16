rule TTP_XOR_MULT_DOSStub_554a {
  strings:
    $key_554a = { 01 22 [2] 75 3a [2] 32 38 [2] 75 29 [2] 3b 25 [2] 37 2f [2] 20 24 [2] 3b 6a [2] 06 }

  condition:
    any of them
}