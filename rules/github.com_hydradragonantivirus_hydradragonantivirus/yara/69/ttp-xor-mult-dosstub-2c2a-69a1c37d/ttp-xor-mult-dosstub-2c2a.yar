rule TTP_XOR_MULT_DOSStub_2c2a {
  strings:
    $key_2c2a = { 78 42 [2] 0c 5a [2] 4b 58 [2] 0c 49 [2] 42 45 [2] 4e 4f [2] 59 44 [2] 42 0a [2] 7f }

  condition:
    any of them
}