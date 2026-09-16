rule TTP_XOR_MULT_DOSStub_7b1a {
  strings:
    $key_7b1a = { 2f 72 [2] 5b 6a [2] 1c 68 [2] 5b 79 [2] 15 75 [2] 19 7f [2] 0e 74 [2] 15 3a [2] 28 }

  condition:
    any of them
}