rule TTP_XOR_MULT_DOSStub_433a {
  strings:
    $key_433a = { 17 52 [2] 63 4a [2] 24 48 [2] 63 59 [2] 2d 55 [2] 21 5f [2] 36 54 [2] 2d 1a [2] 10 }

  condition:
    any of them
}