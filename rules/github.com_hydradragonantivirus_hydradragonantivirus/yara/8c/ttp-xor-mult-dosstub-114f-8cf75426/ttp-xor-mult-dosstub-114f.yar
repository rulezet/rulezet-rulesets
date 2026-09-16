rule TTP_XOR_MULT_DOSStub_114f {
  strings:
    $key_114f = { 45 27 [2] 31 3f [2] 76 3d [2] 31 2c [2] 7f 20 [2] 73 2a [2] 64 21 [2] 7f 6f [2] 42 }

  condition:
    any of them
}