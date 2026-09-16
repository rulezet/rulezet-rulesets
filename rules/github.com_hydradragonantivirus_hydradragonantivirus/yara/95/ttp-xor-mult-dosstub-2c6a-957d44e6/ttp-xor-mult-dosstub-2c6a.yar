rule TTP_XOR_MULT_DOSStub_2c6a {
  strings:
    $key_2c6a = { 78 02 [2] 0c 1a [2] 4b 18 [2] 0c 09 [2] 42 05 [2] 4e 0f [2] 59 04 [2] 42 4a [2] 7f }

  condition:
    any of them
}