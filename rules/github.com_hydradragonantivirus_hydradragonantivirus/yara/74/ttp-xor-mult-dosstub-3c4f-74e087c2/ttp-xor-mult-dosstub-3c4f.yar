rule TTP_XOR_MULT_DOSStub_3c4f {
  strings:
    $key_3c4f = { 68 27 [2] 1c 3f [2] 5b 3d [2] 1c 2c [2] 52 20 [2] 5e 2a [2] 49 21 [2] 52 6f [2] 6f }

  condition:
    any of them
}