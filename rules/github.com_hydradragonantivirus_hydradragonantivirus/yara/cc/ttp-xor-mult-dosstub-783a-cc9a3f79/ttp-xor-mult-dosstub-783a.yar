rule TTP_XOR_MULT_DOSStub_783a {
  strings:
    $key_783a = { 2c 52 [2] 58 4a [2] 1f 48 [2] 58 59 [2] 16 55 [2] 1a 5f [2] 0d 54 [2] 16 1a [2] 2b }

  condition:
    any of them
}