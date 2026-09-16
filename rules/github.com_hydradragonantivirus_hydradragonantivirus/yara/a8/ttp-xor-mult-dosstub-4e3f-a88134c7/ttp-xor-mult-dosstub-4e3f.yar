rule TTP_XOR_MULT_DOSStub_4e3f {
  strings:
    $key_4e3f = { 1a 57 [2] 6e 4f [2] 29 4d [2] 6e 5c [2] 20 50 [2] 2c 5a [2] 3b 51 [2] 20 1f [2] 1d }

  condition:
    any of them
}