rule TTP_XOR_MULT_DOSStub_321a {
  strings:
    $key_321a = { 66 72 [2] 12 6a [2] 55 68 [2] 12 79 [2] 5c 75 [2] 50 7f [2] 47 74 [2] 5c 3a [2] 61 }

  condition:
    any of them
}