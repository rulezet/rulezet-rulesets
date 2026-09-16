rule TTP_XOR_MULT_DOSStub_6c7a {
  strings:
    $key_6c7a = { 38 12 [2] 4c 0a [2] 0b 08 [2] 4c 19 [2] 02 15 [2] 0e 1f [2] 19 14 [2] 02 5a [2] 3f }

  condition:
    any of them
}