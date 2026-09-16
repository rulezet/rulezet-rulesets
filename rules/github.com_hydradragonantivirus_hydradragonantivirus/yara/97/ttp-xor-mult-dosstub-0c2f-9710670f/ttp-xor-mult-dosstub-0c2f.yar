rule TTP_XOR_MULT_DOSStub_0c2f {
  strings:
    $key_0c2f = { 58 47 [2] 2c 5f [2] 6b 5d [2] 2c 4c [2] 62 40 [2] 6e 4a [2] 79 41 [2] 62 0f [2] 5f }

  condition:
    any of them
}