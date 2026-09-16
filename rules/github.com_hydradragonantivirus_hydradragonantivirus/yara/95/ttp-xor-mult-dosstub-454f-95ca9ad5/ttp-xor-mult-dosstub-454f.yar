rule TTP_XOR_MULT_DOSStub_454f {
  strings:
    $key_454f = { 11 27 [2] 65 3f [2] 22 3d [2] 65 2c [2] 2b 20 [2] 27 2a [2] 30 21 [2] 2b 6f [2] 16 }

  condition:
    any of them
}