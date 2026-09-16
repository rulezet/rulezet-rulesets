rule TTP_XOR_MULT_DOSStub_413a {
  strings:
    $key_413a = { 15 52 [2] 61 4a [2] 26 48 [2] 61 59 [2] 2f 55 [2] 23 5f [2] 34 54 [2] 2f 1a [2] 12 }

  condition:
    any of them
}