rule TTP_XOR_MULT_DOSStub_124f {
  strings:
    $key_124f = { 46 27 [2] 32 3f [2] 75 3d [2] 32 2c [2] 7c 20 [2] 70 2a [2] 67 21 [2] 7c 6f [2] 41 }

  condition:
    any of them
}