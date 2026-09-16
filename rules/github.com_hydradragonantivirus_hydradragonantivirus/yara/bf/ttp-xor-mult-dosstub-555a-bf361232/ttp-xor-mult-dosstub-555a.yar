rule TTP_XOR_MULT_DOSStub_555a {
  strings:
    $key_555a = { 01 32 [2] 75 2a [2] 32 28 [2] 75 39 [2] 3b 35 [2] 37 3f [2] 20 34 [2] 3b 7a [2] 06 }

  condition:
    any of them
}