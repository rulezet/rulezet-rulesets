rule TTP_XOR_MULT_DOSStub_4e6f {
  strings:
    $key_4e6f = { 1a 07 [2] 6e 1f [2] 29 1d [2] 6e 0c [2] 20 00 [2] 2c 0a [2] 3b 01 [2] 20 4f [2] 1d }

  condition:
    any of them
}