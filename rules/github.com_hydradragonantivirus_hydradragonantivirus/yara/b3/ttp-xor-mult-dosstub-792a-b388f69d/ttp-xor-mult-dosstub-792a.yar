rule TTP_XOR_MULT_DOSStub_792a {
  strings:
    $key_792a = { 2d 42 [2] 59 5a [2] 1e 58 [2] 59 49 [2] 17 45 [2] 1b 4f [2] 0c 44 [2] 17 0a [2] 2a }

  condition:
    any of them
}