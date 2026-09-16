rule TTP_XOR_MULT_DOSStub_477a {
  strings:
    $key_477a = { 13 12 [2] 67 0a [2] 20 08 [2] 67 19 [2] 29 15 [2] 25 1f [2] 32 14 [2] 29 5a [2] 14 }

  condition:
    any of them
}