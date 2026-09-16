rule TTP_XOR_MULT_DOSStub_707a {
  strings:
    $key_707a = { 24 12 [2] 50 0a [2] 17 08 [2] 50 19 [2] 1e 15 [2] 12 1f [2] 05 14 [2] 1e 5a [2] 23 }

  condition:
    any of them
}