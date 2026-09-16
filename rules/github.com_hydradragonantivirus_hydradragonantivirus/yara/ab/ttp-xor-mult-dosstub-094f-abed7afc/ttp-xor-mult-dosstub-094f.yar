rule TTP_XOR_MULT_DOSStub_094f {
  strings:
    $key_094f = { 5d 27 [2] 29 3f [2] 6e 3d [2] 29 2c [2] 67 20 [2] 6b 2a [2] 7c 21 [2] 67 6f [2] 5a }

  condition:
    any of them
}