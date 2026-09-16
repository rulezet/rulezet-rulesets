rule TTP_XOR_MULT_DOSStub_597a {
  strings:
    $key_597a = { 0d 12 [2] 79 0a [2] 3e 08 [2] 79 19 [2] 37 15 [2] 3b 1f [2] 2c 14 [2] 37 5a [2] 0a }

  condition:
    any of them
}