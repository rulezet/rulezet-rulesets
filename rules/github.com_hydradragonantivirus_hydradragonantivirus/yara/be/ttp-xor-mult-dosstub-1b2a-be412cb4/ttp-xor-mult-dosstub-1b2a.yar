rule TTP_XOR_MULT_DOSStub_1b2a {
  strings:
    $key_1b2a = { 4f 42 [2] 3b 5a [2] 7c 58 [2] 3b 49 [2] 75 45 [2] 79 4f [2] 6e 44 [2] 75 0a [2] 48 }

  condition:
    any of them
}