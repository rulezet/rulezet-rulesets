rule TTP_XOR_MULT_DOSStub_064f {
  strings:
    $key_064f = { 52 27 [2] 26 3f [2] 61 3d [2] 26 2c [2] 68 20 [2] 64 2a [2] 73 21 [2] 68 6f [2] 55 }

  condition:
    any of them
}