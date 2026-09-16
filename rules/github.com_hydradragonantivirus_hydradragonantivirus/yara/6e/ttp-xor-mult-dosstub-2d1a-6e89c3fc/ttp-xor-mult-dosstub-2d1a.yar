rule TTP_XOR_MULT_DOSStub_2d1a {
  strings:
    $key_2d1a = { 79 72 [2] 0d 6a [2] 4a 68 [2] 0d 79 [2] 43 75 [2] 4f 7f [2] 58 74 [2] 43 3a [2] 7e }

  condition:
    any of them
}