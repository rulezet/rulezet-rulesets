rule TTP_XOR_MULT_DOSStub_432a {
  strings:
    $key_432a = { 17 42 [2] 63 5a [2] 24 58 [2] 63 49 [2] 2d 45 [2] 21 4f [2] 36 44 [2] 2d 0a [2] 10 }

  condition:
    any of them
}