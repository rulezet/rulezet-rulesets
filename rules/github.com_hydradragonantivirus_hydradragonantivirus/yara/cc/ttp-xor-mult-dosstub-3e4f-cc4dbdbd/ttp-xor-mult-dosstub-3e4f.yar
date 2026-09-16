rule TTP_XOR_MULT_DOSStub_3e4f {
  strings:
    $key_3e4f = { 6a 27 [2] 1e 3f [2] 59 3d [2] 1e 2c [2] 50 20 [2] 5c 2a [2] 4b 21 [2] 50 6f [2] 6d }

  condition:
    any of them
}