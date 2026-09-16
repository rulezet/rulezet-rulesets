rule TTP_XOR_MULT_DOSStub_7d2a {
  strings:
    $key_7d2a = { 29 42 [2] 5d 5a [2] 1a 58 [2] 5d 49 [2] 13 45 [2] 1f 4f [2] 08 44 [2] 13 0a [2] 2e }

  condition:
    any of them
}