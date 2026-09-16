rule TTP_XOR_MULT_DOSStub_033a {
  strings:
    $key_033a = { 57 52 [2] 23 4a [2] 64 48 [2] 23 59 [2] 6d 55 [2] 61 5f [2] 76 54 [2] 6d 1a [2] 50 }

  condition:
    any of them
}