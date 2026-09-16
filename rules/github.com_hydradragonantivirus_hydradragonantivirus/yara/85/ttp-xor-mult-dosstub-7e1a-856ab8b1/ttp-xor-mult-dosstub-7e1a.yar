rule TTP_XOR_MULT_DOSStub_7e1a {
  strings:
    $key_7e1a = { 2a 72 [2] 5e 6a [2] 19 68 [2] 5e 79 [2] 10 75 [2] 1c 7f [2] 0b 74 [2] 10 3a [2] 2d }

  condition:
    any of them
}