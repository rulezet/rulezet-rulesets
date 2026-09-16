rule TTP_XOR_MULT_DOSStub_467a {
  strings:
    $key_467a = { 12 12 [2] 66 0a [2] 21 08 [2] 66 19 [2] 28 15 [2] 24 1f [2] 33 14 [2] 28 5a [2] 15 }

  condition:
    any of them
}