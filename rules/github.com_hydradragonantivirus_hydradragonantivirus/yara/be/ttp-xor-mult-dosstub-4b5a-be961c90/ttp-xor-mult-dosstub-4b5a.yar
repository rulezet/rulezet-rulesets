rule TTP_XOR_MULT_DOSStub_4b5a {
  strings:
    $key_4b5a = { 1f 32 [2] 6b 2a [2] 2c 28 [2] 6b 39 [2] 25 35 [2] 29 3f [2] 3e 34 [2] 25 7a [2] 18 }

  condition:
    any of them
}