rule TTP_XOR_MULT_DOSStub_2a4f {
  strings:
    $key_2a4f = { 7e 27 [2] 0a 3f [2] 4d 3d [2] 0a 2c [2] 44 20 [2] 48 2a [2] 5f 21 [2] 44 6f [2] 79 }

  condition:
    any of them
}