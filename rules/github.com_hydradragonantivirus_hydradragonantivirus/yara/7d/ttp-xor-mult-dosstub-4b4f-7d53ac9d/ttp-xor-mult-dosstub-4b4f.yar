rule TTP_XOR_MULT_DOSStub_4b4f {
  strings:
    $key_4b4f = { 1f 27 [2] 6b 3f [2] 2c 3d [2] 6b 2c [2] 25 20 [2] 29 2a [2] 3e 21 [2] 25 6f [2] 18 }

  condition:
    any of them
}