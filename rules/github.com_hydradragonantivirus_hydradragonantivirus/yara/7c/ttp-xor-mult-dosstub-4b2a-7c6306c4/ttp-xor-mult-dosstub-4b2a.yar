rule TTP_XOR_MULT_DOSStub_4b2a {
  strings:
    $key_4b2a = { 1f 42 [2] 6b 5a [2] 2c 58 [2] 6b 49 [2] 25 45 [2] 29 4f [2] 3e 44 [2] 25 0a [2] 18 }

  condition:
    any of them
}