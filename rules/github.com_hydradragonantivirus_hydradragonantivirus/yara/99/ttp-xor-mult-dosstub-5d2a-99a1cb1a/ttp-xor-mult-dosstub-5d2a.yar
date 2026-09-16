rule TTP_XOR_MULT_DOSStub_5d2a {
  strings:
    $key_5d2a = { 09 42 [2] 7d 5a [2] 3a 58 [2] 7d 49 [2] 33 45 [2] 3f 4f [2] 28 44 [2] 33 0a [2] 0e }

  condition:
    any of them
}