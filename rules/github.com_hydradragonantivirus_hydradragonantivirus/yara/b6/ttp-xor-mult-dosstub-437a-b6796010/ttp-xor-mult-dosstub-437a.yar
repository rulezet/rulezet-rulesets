rule TTP_XOR_MULT_DOSStub_437a {
  strings:
    $key_437a = { 17 12 [2] 63 0a [2] 24 08 [2] 63 19 [2] 2d 15 [2] 21 1f [2] 36 14 [2] 2d 5a [2] 10 }

  condition:
    any of them
}