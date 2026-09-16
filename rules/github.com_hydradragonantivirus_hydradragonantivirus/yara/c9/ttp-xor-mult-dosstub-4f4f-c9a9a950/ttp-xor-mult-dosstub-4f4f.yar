rule TTP_XOR_MULT_DOSStub_4f4f {
  strings:
    $key_4f4f = { 1b 27 [2] 6f 3f [2] 28 3d [2] 6f 2c [2] 21 20 [2] 2d 2a [2] 3a 21 [2] 21 6f [2] 1c }

  condition:
    any of them
}