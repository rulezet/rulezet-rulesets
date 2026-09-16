rule TTP_XOR_MULT_DOSStub_781a {
  strings:
    $key_781a = { 2c 72 [2] 58 6a [2] 1f 68 [2] 58 79 [2] 16 75 [2] 1a 7f [2] 0d 74 [2] 16 3a [2] 2b }

  condition:
    any of them
}