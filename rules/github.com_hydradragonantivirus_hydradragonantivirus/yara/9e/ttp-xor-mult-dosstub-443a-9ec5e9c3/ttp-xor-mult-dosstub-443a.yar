rule TTP_XOR_MULT_DOSStub_443a {
  strings:
    $key_443a = { 10 52 [2] 64 4a [2] 23 48 [2] 64 59 [2] 2a 55 [2] 26 5f [2] 31 54 [2] 2a 1a [2] 17 }

  condition:
    any of them
}