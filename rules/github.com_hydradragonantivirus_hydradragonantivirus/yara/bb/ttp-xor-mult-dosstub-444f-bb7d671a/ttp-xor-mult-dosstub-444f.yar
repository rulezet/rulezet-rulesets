rule TTP_XOR_MULT_DOSStub_444f {
  strings:
    $key_444f = { 10 27 [2] 64 3f [2] 23 3d [2] 64 2c [2] 2a 20 [2] 26 2a [2] 31 21 [2] 2a 6f [2] 17 }

  condition:
    any of them
}