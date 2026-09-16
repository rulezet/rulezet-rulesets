rule TTP_XOR_MULT_DOSStub_787a {
  strings:
    $key_787a = { 2c 12 [2] 58 0a [2] 1f 08 [2] 58 19 [2] 16 15 [2] 1a 1f [2] 0d 14 [2] 16 5a [2] 2b }

  condition:
    any of them
}