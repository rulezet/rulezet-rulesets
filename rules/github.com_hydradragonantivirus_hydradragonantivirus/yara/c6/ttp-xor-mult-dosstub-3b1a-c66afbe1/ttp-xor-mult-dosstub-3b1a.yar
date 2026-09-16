rule TTP_XOR_MULT_DOSStub_3b1a {
  strings:
    $key_3b1a = { 6f 72 [2] 1b 6a [2] 5c 68 [2] 1b 79 [2] 55 75 [2] 59 7f [2] 4e 74 [2] 55 3a [2] 68 }

  condition:
    any of them
}