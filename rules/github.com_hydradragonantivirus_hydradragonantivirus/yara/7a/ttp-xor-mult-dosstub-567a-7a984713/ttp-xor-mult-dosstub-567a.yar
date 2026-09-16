rule TTP_XOR_MULT_DOSStub_567a {
  strings:
    $key_567a = { 02 12 [2] 76 0a [2] 31 08 [2] 76 19 [2] 38 15 [2] 34 1f [2] 23 14 [2] 38 5a [2] 05 }

  condition:
    any of them
}