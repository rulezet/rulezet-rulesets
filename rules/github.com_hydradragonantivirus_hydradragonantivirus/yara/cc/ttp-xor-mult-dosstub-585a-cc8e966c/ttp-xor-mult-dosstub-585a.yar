rule TTP_XOR_MULT_DOSStub_585a {
  strings:
    $key_585a = { 0c 32 [2] 78 2a [2] 3f 28 [2] 78 39 [2] 36 35 [2] 3a 3f [2] 2d 34 [2] 36 7a [2] 0b }

  condition:
    any of them
}