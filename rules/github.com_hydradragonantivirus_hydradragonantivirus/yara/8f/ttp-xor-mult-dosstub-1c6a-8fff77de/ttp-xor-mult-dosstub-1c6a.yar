rule TTP_XOR_MULT_DOSStub_1c6a {
  strings:
    $key_1c6a = { 48 02 [2] 3c 1a [2] 7b 18 [2] 3c 09 [2] 72 05 [2] 7e 0f [2] 69 04 [2] 72 4a [2] 4f }

  condition:
    any of them
}