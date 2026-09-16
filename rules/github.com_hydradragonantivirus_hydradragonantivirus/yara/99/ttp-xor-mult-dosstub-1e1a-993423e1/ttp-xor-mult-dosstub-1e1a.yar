rule TTP_XOR_MULT_DOSStub_1e1a {
  strings:
    $key_1e1a = { 4a 72 [2] 3e 6a [2] 79 68 [2] 3e 79 [2] 70 75 [2] 7c 7f [2] 6b 74 [2] 70 3a [2] 4d }

  condition:
    any of them
}