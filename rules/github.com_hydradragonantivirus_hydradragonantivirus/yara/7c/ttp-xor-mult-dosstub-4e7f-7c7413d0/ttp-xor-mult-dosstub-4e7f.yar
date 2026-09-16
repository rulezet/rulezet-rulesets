rule TTP_XOR_MULT_DOSStub_4e7f {
  strings:
    $key_4e7f = { 1a 17 [2] 6e 0f [2] 29 0d [2] 6e 1c [2] 20 10 [2] 2c 1a [2] 3b 11 [2] 20 5f [2] 1d }

  condition:
    any of them
}