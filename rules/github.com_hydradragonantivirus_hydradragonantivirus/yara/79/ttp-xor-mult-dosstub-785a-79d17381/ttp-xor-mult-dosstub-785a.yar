rule TTP_XOR_MULT_DOSStub_785a {
  strings:
    $key_785a = { 2c 32 [2] 58 2a [2] 1f 28 [2] 58 39 [2] 16 35 [2] 1a 3f [2] 0d 34 [2] 16 7a [2] 2b }

  condition:
    any of them
}