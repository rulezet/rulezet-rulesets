rule TTP_XOR_MULT_DOSStub_2d2a {
  strings:
    $key_2d2a = { 79 42 [2] 0d 5a [2] 4a 58 [2] 0d 49 [2] 43 45 [2] 4f 4f [2] 58 44 [2] 43 0a [2] 7e }

  condition:
    any of them
}