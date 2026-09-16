rule TTP_XOR_MULT_DOSStub_0b1a {
  strings:
    $key_0b1a = { 5f 72 [2] 2b 6a [2] 6c 68 [2] 2b 79 [2] 65 75 [2] 69 7f [2] 7e 74 [2] 65 3a [2] 58 }

  condition:
    any of them
}