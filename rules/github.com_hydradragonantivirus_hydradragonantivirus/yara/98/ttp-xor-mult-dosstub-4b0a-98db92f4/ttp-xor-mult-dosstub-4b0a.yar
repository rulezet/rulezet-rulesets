rule TTP_XOR_MULT_DOSStub_4b0a {
  strings:
    $key_4b0a = { 1f 62 [2] 6b 7a [2] 2c 78 [2] 6b 69 [2] 25 65 [2] 29 6f [2] 3e 64 [2] 25 2a [2] 18 }

  condition:
    any of them
}