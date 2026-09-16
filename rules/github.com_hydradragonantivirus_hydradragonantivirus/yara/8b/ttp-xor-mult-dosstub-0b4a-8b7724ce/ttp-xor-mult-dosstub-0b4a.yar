rule TTP_XOR_MULT_DOSStub_0b4a {
  strings:
    $key_0b4a = { 5f 22 [2] 2b 3a [2] 6c 38 [2] 2b 29 [2] 65 25 [2] 69 2f [2] 7e 24 [2] 65 6a [2] 58 }

  condition:
    any of them
}