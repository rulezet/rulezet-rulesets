rule TTP_XOR_MULT_DOSStub_1e3a {
  strings:
    $key_1e3a = { 4a 52 [2] 3e 4a [2] 79 48 [2] 3e 59 [2] 70 55 [2] 7c 5f [2] 6b 54 [2] 70 1a [2] 4d }

  condition:
    any of them
}