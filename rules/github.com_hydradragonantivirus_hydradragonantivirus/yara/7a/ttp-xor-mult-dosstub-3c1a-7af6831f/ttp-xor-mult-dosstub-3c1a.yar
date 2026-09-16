rule TTP_XOR_MULT_DOSStub_3c1a {
  strings:
    $key_3c1a = { 68 72 [2] 1c 6a [2] 5b 68 [2] 1c 79 [2] 52 75 [2] 5e 7f [2] 49 74 [2] 52 3a [2] 6f }

  condition:
    any of them
}