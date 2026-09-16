rule TTP_XOR_MULT_DOSStub_420a {
  strings:
    $key_420a = { 16 62 [2] 62 7a [2] 25 78 [2] 62 69 [2] 2c 65 [2] 20 6f [2] 37 64 [2] 2c 2a [2] 11 }

  condition:
    any of them
}