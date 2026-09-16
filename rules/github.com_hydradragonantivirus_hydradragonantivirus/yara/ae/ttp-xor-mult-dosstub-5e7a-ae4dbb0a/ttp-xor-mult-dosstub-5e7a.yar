rule TTP_XOR_MULT_DOSStub_5e7a {
  strings:
    $key_5e7a = { 0a 12 [2] 7e 0a [2] 39 08 [2] 7e 19 [2] 30 15 [2] 3c 1f [2] 2b 14 [2] 30 5a [2] 0d }

  condition:
    any of them
}