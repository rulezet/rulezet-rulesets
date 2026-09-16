rule TTP_XOR_MULT_DOSStub_5e4f {
  strings:
    $key_5e4f = { 0a 27 [2] 7e 3f [2] 39 3d [2] 7e 2c [2] 30 20 [2] 3c 2a [2] 2b 21 [2] 30 6f [2] 0d }

  condition:
    any of them
}