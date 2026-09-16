rule TTP_XOR_MULT_DOSStub_003a {
  strings:
    $key_003a = { 54 52 [2] 20 4a [2] 67 48 [2] 20 59 [2] 6e 55 [2] 62 5f [2] 75 54 [2] 6e 1a [2] 53 }

  condition:
    any of them
}