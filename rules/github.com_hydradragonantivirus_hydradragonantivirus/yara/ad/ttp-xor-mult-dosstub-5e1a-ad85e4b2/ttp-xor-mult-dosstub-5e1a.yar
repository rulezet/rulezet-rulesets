rule TTP_XOR_MULT_DOSStub_5e1a {
  strings:
    $key_5e1a = { 0a 72 [2] 7e 6a [2] 39 68 [2] 7e 79 [2] 30 75 [2] 3c 7f [2] 2b 74 [2] 30 3a [2] 0d }

  condition:
    any of them
}