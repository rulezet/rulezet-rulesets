rule TTP_XOR_MULT_DOSStub_0cff {
  strings:
    $key_0cff = { 58 97 [2] 2c 8f [2] 6b 8d [2] 2c 9c [2] 62 90 [2] 6e 9a [2] 79 91 [2] 62 df [2] 5f }

  condition:
    any of them
}