rule TTP_XOR_MULT_DOSStub_542a {
  strings:
    $key_542a = { 00 42 [2] 74 5a [2] 33 58 [2] 74 49 [2] 3a 45 [2] 36 4f [2] 21 44 [2] 3a 0a [2] 07 }

  condition:
    any of them
}