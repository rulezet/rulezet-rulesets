rule TTP_XOR_MULT_DOSStub_7e7a {
  strings:
    $key_7e7a = { 2a 12 [2] 5e 0a [2] 19 08 [2] 5e 19 [2] 10 15 [2] 1c 1f [2] 0b 14 [2] 10 5a [2] 2d }

  condition:
    any of them
}