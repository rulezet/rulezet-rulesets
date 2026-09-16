rule TTP_XOR_MULT_DOSStub_4b3a {
  strings:
    $key_4b3a = { 1f 52 [2] 6b 4a [2] 2c 48 [2] 6b 59 [2] 25 55 [2] 29 5f [2] 3e 54 [2] 25 1a [2] 18 }

  condition:
    any of them
}