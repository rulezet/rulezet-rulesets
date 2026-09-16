rule TTP_XOR_MULT_DOSStub_1e4f {
  strings:
    $key_1e4f = { 4a 27 [2] 3e 3f [2] 79 3d [2] 3e 2c [2] 70 20 [2] 7c 2a [2] 6b 21 [2] 70 6f [2] 4d }

  condition:
    any of them
}