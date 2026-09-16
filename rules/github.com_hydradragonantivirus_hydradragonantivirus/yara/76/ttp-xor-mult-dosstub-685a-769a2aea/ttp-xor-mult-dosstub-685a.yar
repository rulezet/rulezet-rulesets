rule TTP_XOR_MULT_DOSStub_685a {
  strings:
    $key_685a = { 3c 32 [2] 48 2a [2] 0f 28 [2] 48 39 [2] 06 35 [2] 0a 3f [2] 1d 34 [2] 06 7a [2] 3b }

  condition:
    any of them
}