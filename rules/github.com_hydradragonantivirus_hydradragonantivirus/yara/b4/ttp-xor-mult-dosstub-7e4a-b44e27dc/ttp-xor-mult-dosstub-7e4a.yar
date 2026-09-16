rule TTP_XOR_MULT_DOSStub_7e4a {
  strings:
    $key_7e4a = { 2a 22 [2] 5e 3a [2] 19 38 [2] 5e 29 [2] 10 25 [2] 1c 2f [2] 0b 24 [2] 10 6a [2] 2d }

  condition:
    any of them
}